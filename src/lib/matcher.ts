/**
 * Vulnerability Matcher — Match packages against OSV advisory data.
 * Supports semver (npm, crates.io), PEP 440 (PyPI), and Maven versioning (Java).
 * Handles range matching, deduplication, severity extraction.
 */
import type { PackageRef, Finding } from "./types.ts";
import { SeverityOrder, sortBySeverity } from "./types.ts";

/** Summary prefix GitHub attaches to advisories marked as duplicates of another advisory. */
const DUPLICATE_ADVISORY_PREFIX = "Duplicate Advisory:";

function isDuplicateMirror(entry: any): boolean {
  return typeof entry?.summary === "string" && entry.summary.startsWith(DUPLICATE_ADVISORY_PREFIX);
}

/** Range event types that bound the affected set — evidence of a fix. */
const TERMINATOR_EVENTS = ["fixed", "last_affected", "latest", "deprecated"];

function hasFixBoundary(range: { events?: unknown[] }): boolean {
  for (const ev of range.events || []) {
    if (ev && typeof ev === "object" && TERMINATOR_EVENTS.some(k => k in (ev as Record<string, unknown>))) return true;
  }
  return false;
}

function affectedKey(affected: any, entryEcosystem?: string): string | null {
  const name = affected?.package?.name;
  const eco = affected?.package?.ecosystem ?? entryEcosystem;
  if (!name || !eco) return null;
  return `${String(eco).toLowerCase()}\u0000${String(name).toLowerCase()}`;
}

/**
 * Drop "Duplicate Advisory" mirror records whose affected packages are all bounded by
 * fix data in non-duplicate records. GitHub marks duplicate advisories as mirrors of the
 * original, but their OSV copies often lose the fixed version and carry unbounded ranges
 * (e.g. introduced=3.0.0, no fixed), which flag patched versions already covered by the
 * authoritative primary. Mirrors are kept when no fix boundary exists for an affected
 * package — over-reporting beats missing a real vulnerability.
 */
export function dropShadowedDuplicates(entries: any[]): any[] {
  const bounded = new Set<string>();
  for (const e of entries) {
    if (!e || isDuplicateMirror(e)) continue;
    for (const aff of e.affected || []) {
      const key = affectedKey(aff, e.ecosystems?.[0]);
      if (key && (aff.ranges || []).some(hasFixBoundary)) bounded.add(key);
    }
  }

  return entries.filter(e => {
    if (!e || !isDuplicateMirror(e)) return true;
    const blocks = e.affected || [];
    if (blocks.length === 0) return true;
    const allShadowed = blocks.every((aff: any) => {
      const key = affectedKey(aff, e.ecosystems?.[0]);
      return key !== null && bounded.has(key);
    });
    return !allShadowed;
  });
}

/**
 * Match a list of packages against OSV vulnerability data.
 * Returns findings sorted by severity (CRITICAL first).
 */
export function matchVulnerabilities(packages: PackageRef[], osvData: any[]): Finding[] {
  const entries = dropShadowedDuplicates(osvData);
  const rawFindings: Finding[] = [];

  for (const pkg of packages) {
    for (const entry of entries) {
      // Skip entries not relevant to this ecosystem
      if (!matchesEcosystem(entry, pkg.ecosystem)) continue;

      // Check if installed version is affected (route to correct version scheme)
      const result = checkAffected(pkg.name, pkg.version, pkg.ecosystem, entry);
      if (!result.isAffected) continue;

      // Determine severity from CVSS scores
      const severity = extractSeverity(entry);

      // Collect fixed versions from the matching affected block only
      const fixedVersions = collectFixedVersions(entry, pkg.name, pkg.ecosystem);

      // Build finding
      rawFindings.push({
        id: entry.id,
        aliases: entry.aliases || [],
        ecosystem: pkg.ecosystem,
        packageName: pkg.name,
        installedVersion: pkg.version,
        vulnerableRange: result.range || `=${pkg.version}`,
        fixedVersions,
        severity,
        summary: entry.summary || `${pkg.name}@${pkg.version} has a known vulnerability`,
        references: extractReferences(entry),
      });
    }
  }

  // Deduplicate: same CVE/GHSA + same package = one finding
  const unique = deduplicate(rawFindings);

  // Sort by severity (descending), then package name
  return sortBySeverity(unique);
}

/** Check if an OSV entry applies to a given ecosystem */
function matchesEcosystem(entry: any, ecosystem: string): boolean {
  const ecosystems = entry.ecosystems || [];

  // Normalize comparison — OSV uses uppercase (NPM), we may use lowercase (npm)
  const normalizedEcosystems = ecosystems.map((e: string) => e.toLowerCase());
  return normalizedEcosystems.includes(ecosystem.toLowerCase());
}

interface AffectedResult {
  isAffected: boolean;
  range?: string;
}

/** Check if a specific version falls within the affected range of an OSV entry */
function checkAffected(packageName: string, version: string, ecosystem: string, entry: any): AffectedResult {
  const cleanVersion = version.replace(/^v/, "").replace(/^[~^]/, "");
  const eco = ecosystem.toLowerCase();
  const pkgNameNorm = eco === "pypi" ? normalizePyPIName(packageName) : packageName.toLowerCase();

  let rangeMatch: AffectedResult | null = null;

  for (const affected of entry.affected || []) {
    if (!isSamePackage(pkgNameNorm, affected, eco)) continue;

    // Try exact version list — an explicit vendor statement, never excluded
    const exactResult = tryExactVersion(cleanVersion, affected);
    if (exactResult.isAffected) return exactResult;

    // GHSA-curated advisories state affected versions explicitly; their auto-derived
    // ECOSYSTEM ranges are coarse bounds that over-cover backported lines (e.g. fixed
    // in 12.0.12 but backported to 11.0.27 — the range still flags 11.0.29). When a
    // curated list exists and does not name the installed version, trust it over ranges.
    if (isCuratedListAuthoritative(entry.id, affected)) continue;
    // Try range matching (ecosystem-routed)
    const rangeResult = tryRanges(cleanVersion, affected, eco);
    if (rangeResult.isAffected && !rangeMatch) rangeMatch = rangeResult;
  }

  if (!rangeMatch) return { isAffected: false };

  // Parallel release lines (Maven backport / LTS branches): a version at or above
  // a fixed version on its own line is patched even when another range's window
  // numerically contains it.
  if (isPatchedByParallelLineFix(cleanVersion, entry, packageName, eco)) return { isAffected: false };

  return rangeMatch;
}

/** Check if an affected block refers to the same package */
function isSamePackage(pkgNameNorm: string, affected: { package?: { name?: string } }, eco: string): boolean {
  const advName = affected.package?.name ?? "";
  const advNameNorm = eco === "pypi" ? normalizePyPIName(advName) : advName.toLowerCase();
  return pkgNameNorm === advNameNorm;
}

/** Try matching against the flat versions array */
function tryExactVersion(version: string, affected: { versions?: string[] }): AffectedResult {
  if (affected.versions?.includes(version)) {
    return { isAffected: true, range: affected.versions.join(", ") };
  }
  return { isAffected: false };
}

/** GHSA entries carry vendor-curated version lists; their auto-derived ranges are coarse bounds only. */
function isCuratedListAuthoritative(id: string | undefined, affected: { versions?: string[] }): boolean {
  if (!id?.startsWith("GHSA-")) return false;
  return Array.isArray(affected.versions) && affected.versions.length > 0;
}

/** Try all range-based matching with ecosystem routing */
function tryRanges(version: string, affected: { ranges?: Array<{ type?: string; events?: unknown[]; representations?: Array<{ range?: string; type?: string }> }> }, eco: string): AffectedResult {
  for (const r of affected.ranges || []) {
    // ECOSYSTEM/GIT event-based ranges
    const eventResult = tryEventRange(version, r, eco);
    if (eventResult.isAffected) return eventResult;

    // Representation-based ranges (SEMVER, PEP440, Maven)
    const repResult = tryRepresentationRanges(version, r, eco);
    if (repResult.isAffected) return repResult;
  }
  return { isAffected: false };
}

/** Match against ECOSYSTEM or GIT event-based ranges */
function tryEventRange(version: string, range: { type?: string; events?: unknown[]; database_specific?: { extracted_events?: unknown[] } }, eco: string): AffectedResult {
  if (!range.events || !(range.type === "ECOSYSTEM" || range.type === "GIT")) return { isAffected: false };
  const extracted = range.database_specific?.extracted_events;
  const eventsToUse = extracted && extracted.length > 0 ? extracted : range.events;
  return matchesEcosystemEvents(version, eventsToUse as EcoEvent[], eco);
}

/** Match against representation-level ranges (semver, pep440, maven) */
function tryRepresentationRanges(version: string, range: { representations?: Array<{ range?: string; type?: string }> }, eco: string): AffectedResult {
  for (const rep of range.representations || []) {
    if (!rep.range) continue;
    const result = matchSingleRepresentation(version, rep.range, rep.type, eco);
    if (result.isAffected) return result;
  }
  return { isAffected: false };
}

/** Route a single range string to the correct version scheme */
function matchSingleRepresentation(version: string, rangeStr: string, rangeType: string | undefined, eco: string): AffectedResult {
  if (eco === "pypi") {
    return matchesPEP440Range(version, rangeStr)
      ? { isAffected: true, range: rangeStr }
      : { isAffected: false };
  }
  if (eco === "maven") {
    return matchesMavenRange(version, rangeStr)
      ? { isAffected: true, range: rangeStr }
      : { isAffected: false };
  }
  // npm, crates.io, Go → semver
  if (rangeType === "SEMVER" && matchesSemverRange(version, rangeStr)) {
    return { isAffected: true, range: rangeStr };
  }
  return { isAffected: false };
}

// ─── PEP 440 (Python) ──────────────────────────────────────

/**
 * Parse a PEP 440 version into a single comparable number.
 * Handles: 1, 1.0, 1.0.post1, 1.0a1, 1.0b2, 1.0rc1, 1.0.dev3
 *
 * Encoding: base * 10^8 + pre_offset
 *   release 1.2.3 → 1*1e8 + 2*1e6 + 3*1e4 = 102030000
 *   alpha/beta/rc add small offsets so they sort before release
 *   post adds after release, dev subtracts
 */
function parsePEP440Number(version: string): number {
  const cleaned = version.trim().replace(/^\d+!/, ""); // strip epoch prefix
  const firstM = /^(\d+)/.exec(cleaned);
  if (!firstM) {
    return Number.parseInt(cleaned, 10) * 10_000 || 0;
  }
  let rest = cleaned.slice(firstM[0].length);
  const nums: number[] = [Number.parseInt(firstM[1], 10)];
  for (let k = 0; k < 2; k++) {
    const partM = /^\.\d+/.exec(rest);
    if (!partM) break;
    nums.push(Number.parseInt(partM[0].slice(1), 10));
    rest = rest.slice(partM[0].length);
  }
  const major = nums[0] ?? 0;
  const minor = nums[1] ?? 0;
  const micro = nums[2] ?? 0;
  const base = major * 100_000_000 + minor * 1_000_000 + micro * 10_000;
  let hasPre = false;
  let preN = 0;
  const preM = /^(rc|[ab])(\d+)?/.exec(rest);
  if (preM) {
    hasPre = true;
    rest = rest.slice(preM[0].length);
    preN = preM[2] ? Number.parseInt(preM[2], 10) : 0;
  }
  const phase = pep440PrePhase(preM);
  let postN: number | null = null;
  const postM = /^\.post(\d+)/.exec(rest);
  if (postM) {
    rest = rest.slice(postM[0].length);
    postN = Number.parseInt(postM[1], 10);
  }
  let devN: number | null = null;
  const devM = /^\.dev(\d+)/.exec(rest);
  if (devM) {
    rest = rest.slice(devM[0].length);
    devN = Number.parseInt(devM[1], 10);
  }
  if (rest !== "") {
    return Number.parseInt(cleaned, 10) * 10_000 || 0;
  }
  return finishPep440(base, hasPre, phase, preN, postN, devN);
}

/** PEP 440 pre-release phase offset: alpha < beta < rc. */
function pep440PrePhase(preM: RegExpExecArray | null): number {
  if (!preM) return 0;
  if (preM[1] === "b") return 100;
  if (preM[1] === "rc") return 200;
  return 0;
}

/** Combine PEP 440 components into a sortable number (post > release > dev/pre). */
function finishPep440(
  base: number,
  hasPre: boolean,
  phase: number,
  preN: number,
  postN: number | null,
  devN: number | null,
): number {
  if (postN !== null) {
    return base + 1 + postN / 1000;
  }
  if (devN !== null && !hasPre) {
    return base - 5000 - devN / 1000;
  }
  if (hasPre) {
    // pre-release sorts before the final release: a < b < rc < release
    return base - 400 + phase + preN / 1000;
  }
  return base;
}

/** Compare two PEP 440 versions. Returns negative, zero, or positive. */
export function comparePEP440(a: string, b: string): number {
  return parsePEP440Number(a) - parsePEP440Number(b);
}

/** Normalize PyPI package name (PEP 50): collapse -, _, whitespace to single dash */
export function normalizePyPIName(name: string): string {
  return name.toLowerCase().replace(/[\s_-]+/g, "-").trim();
}

/** Match a version against a PEP 440 range string like ">=1.0,<2.0" or "~=1.4" */
export function matchesPEP440Range(version: string, range: string): boolean {
  const v = version.trim();
  // Handle OR groups separated by "||"
  const orGroups = range.split(/\|\|/).map(g => g.trim());
  if (orGroups.length > 1) {
    return orGroups.some(group => matchesPEP440Constraints(v, group));
  }
  return matchesPEP440Constraints(v, range);
}

/** Match against AND-ed constraints (comma or space separated) */
function matchesPEP440Constraints(version: string, range: string): boolean {
  const constraints = range.split(/[, ]+/).map(s => s.trim()).filter(Boolean);

  for (const c of constraints) {
    if (!checkConstraint(version, c)) return false;
  }

  return true;
}

/** Check a single PEP 440 constraint against a version */
function checkConstraint(version: string, c: string): boolean {
  // ~=1.4 is >=1.4,==1.* ; ~=1.4.5 is >=1.4.5,==1.4.*
  const compatMatch = /^~=(\d+(?:\.\d+)+)$/.exec(c);
  if (compatMatch) return checkCompatibleRelease(version, compatMatch[1]);

  // ==3.* matches 3.x ; ==1.4.* matches 1.4.x
  const wildMatch = /^==(\d+(?:\.\d+)*)\.\*$/.exec(c);
  if (wildMatch) return checkWildcard(version, wildMatch[1]);

  // Standard operators: >=, <=, >, <, ==, !=
  const opMatch = /^(>=|<=|>|<|==|!=)(.+)$/.exec(c);
  if (opMatch) return checkOperator(version, opMatch);

  return false;
}

/** PEP 440 compatible release. Upper bound bumps the second-to-last component. */
function checkCompatibleRelease(version: string, spec: string): boolean {
  const parts = spec.split(".");
  if (parts.length < 2) return false;
  const stem = parts.slice(0, -1);
  const bumped = stem.map((part, i) => (i === stem.length - 1 ? String(Number.parseInt(part, 10) + 1) : part));
  if (comparePEP440(version, spec) < 0) return false;
  return comparePEP440(version, bumped.join(".")) < 0;
}

/** Check == wildcard constraint. `prefix` is the series before `.*`. */
function checkWildcard(version: string, prefix: string): boolean {
  const want = prefix.split(".");
  const got = version.split(".").map(part => /^\d+/.exec(part)?.[0] ?? "");
  if (got.length < want.length) return false;
  return want.every((part, i) => got[i] === part);
}

/** Check standard operator constraint */
function checkOperator(version: string, m: RegExpMatchArray): boolean {
  const [, op, target] = m;
  const cmp = comparePEP440(version, target.trim());
  switch (op) {
    case ">=": return cmp >= 0;
    case "<=": return cmp <= 0;
    case ">": return cmp > 0;
    case "<": return cmp < 0;
    case "==": return cmp === 0;
    case "!=": return cmp !== 0;
    default: return true;
  }
}

// ─── Maven Versioning (Java) ────────────────────────────────

/**
 * Qualifier rank. Negative so a pre-release stays below the zero pad of a shorter release
 * (`1.0-alpha` < `1.0`). `ga` / `final` / `release` share the release rank.
 */
const MAVEN_QUALIFIERS: Record<string, number> = {
  alpha: -6,
  a: -6,
  beta: -5,
  b: -5,
  milestone: -4,
  m: -4,
  rc: -3,
  cr: -3,
  snapshot: -2,
  snap: -2,
  ga: 0,
  final: 0,
  release: 0,
  sp: 1,
};

function mavenQualifier(token: string): number[] {
  const lower = token.toLowerCase();
  if (lower in MAVEN_QUALIFIERS) return [MAVEN_QUALIFIERS[lower], 0];
  const glued = /^([a-z]+)(\d+)$/.exec(lower);
  if (glued && glued[1] in MAVEN_QUALIFIERS) {
    return [MAVEN_QUALIFIERS[glued[1]], Number.parseInt(glued[2], 10)];
  }
  // Unknown qualifier still sorts before the release pad.
  return [-1, 0];
}

/** Parse Maven version into a comparable numeric array. */
function parseMavenParts(version: string): number[] {
  const cleaned = version.replace(/^v/, "");
  const parts = cleaned.split(/[.-]/).filter(p => p.length > 0);
  const nums: number[] = [];

  for (const p of parts) {
    if (/^\d+$/.test(p)) {
      nums.push(Number.parseInt(p, 10));
    } else {
      nums.push(...mavenQualifier(p));
    }
  }

  while (nums.length < 3) nums.push(0);
  return nums;
}

/** Compare two Maven versions. Returns negative, zero, or positive. */
export function compareMavenVersion(a: string, b: string): number {
  const pa = parseMavenParts(a);
  const pb = parseMavenParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va !== vb) return va - vb;
  }
  return 0;
}

/** Skip leading separators (commas/spaces) in a Maven range string. */
function skipRangeSeparators(range: string, i: number): number {
  while (i < range.length && (range[i] === "," || range[i] === " ")) i++;
  return i;
}

/** Split a Maven range into bracketed restrictions. Commas inside brackets stay put. */
function splitMavenRangeIntervals(range: string): string[] {
  const intervals: string[] = [];
  let i = 0;
  while (i < range.length) {
    i = skipRangeSeparators(range, i);
    if (i >= range.length) break;
    const open = range[i];
    if (open !== "[" && open !== "(") return [];
    let end = -1;
    for (let j = i + 1; j < range.length; j++) {
      if (range[j] === "]" || range[j] === ")") {
        end = j;
        break;
      }
    }
    if (end < 0) return [];
    intervals.push(range.slice(i, end + 1));
    i = end + 1;
  }
  return intervals;
}

/** Match a version against a Maven range like "[1.0,2.0)" or "(,1.0]" or "(1.0,2.0]" */
export function matchesMavenRange(version: string, range: string): boolean {
  const intervals = splitMavenRangeIntervals(range.trim());
  if (intervals.length === 0) return false;
  return intervals.some(sub => checkMavenSubRange(sub, version));
}

/** Check one bracketed Maven restriction. Unparsed input does not match. */
function checkMavenSubRange(sub: string, version: string): boolean {
  const fullMatch = /^([[(])([^,]*),([^)\]]*)([)\]])$/.exec(sub);
  if (fullMatch) return checkFullInterval(fullMatch, version);

  const loOnly = /^([[(])([^()\]]+)([)\]])$/.exec(sub);
  if (loOnly) return checkLowerBound(loOnly, version);

  return false;
}

/** Check full interval [lo,hi) or (lo,hi] */
function checkFullInterval(m: RegExpMatchArray, version: string): boolean {
  const [, loB, loV, hiV, hiB] = m;
  let loOk = true;
  let hiOk = true;
  if (loV.trim()) {
    const loCmp = compareMavenVersion(version, loV.trim());
    loOk = loB === "[" ? loCmp >= 0 : loCmp > 0;
  }
  if (hiV.trim()) {
    const hiCmp = compareMavenVersion(version, hiV.trim());
    hiOk = hiB === "]" ? hiCmp <= 0 : hiCmp < 0;
  }
  return loOk && hiOk;
}

/** Check lower-bound-only constraint */
function checkLowerBound(m: RegExpMatchArray, version: string): boolean {
  const [, br, val] = m;
  const cmp = compareMavenVersion(version, val.trim());
  return br === "[" ? cmp >= 0 : cmp > 0;
}

// ─── ECOSYSTEM Events (OSV standard for Maven/npm/Pypi) ──────

interface AffectedEventResult {
  isAffected: boolean;
  range?: string;
}

/** Compare versions for ECOSYSTEM event ranges (and fix planning). */
export function comparePackageVersion(a: string, b: string, ecosystem: string): number {
  const eco = ecosystem.toLowerCase();
  if (eco === "maven") return compareMavenVersion(a, b);
  if (eco === "pypi") return comparePEP440(a, b);
  return compareSemver(a, b);
}

interface EventSegment {
  introduced: string;
  fixed: string | null;
  last_affected: string | null;
}

function parseEventSegments(
  events: Array<{ introduced?: string; fixed?: string; deprecated?: string; latest?: string; last_affected?: string }>,
): EventSegment[] {
  const segments: EventSegment[] = [];
  let current: EventSegment = { introduced: "0", fixed: null, last_affected: null };

  const pushCurrent = () => {
    segments.push(current);
    current = { introduced: "0", fixed: null, last_affected: null };
  };

  for (const ev of events) {
    if (ev.introduced !== undefined) {
      if (current.fixed !== null || current.last_affected !== null || current.introduced !== "0") {
        pushCurrent();
      }
      current.introduced = ev.introduced || "0";
      current.fixed = null;
      current.last_affected = null;
    }
    // Terminators: `fixed` is exclusive (first non-affected version);
    // last_affected / latest / deprecated are inclusive (last affected version).
    if (ev.fixed) {
      current.fixed = ev.fixed;
      current.last_affected = null;
    } else {
      const inclusiveEnd = ev.last_affected || ev.latest || ev.deprecated;
      if (inclusiveEnd) {
        current.last_affected = inclusiveEnd;
        current.fixed = null;
      }
    }
  }

  segments.push(current);
  return segments;
}

function versionInEventSegment(version: string, segment: EventSegment, ecosystem: string): boolean {
  const cmp = (a: string, b: string) => comparePackageVersion(a, b, ecosystem);
  if (cmp(version, segment.introduced) < 0) return false;
  if (segment.fixed !== null && cmp(version, segment.fixed) >= 0) return false;
  if (segment.last_affected !== null && cmp(version, segment.last_affected) > 0) return false;
  return true;
}

/** OSV ECOSYSTEM/GIT range event */
type EcoEvent = { introduced?: string; fixed?: string; deprecated?: string; latest?: string; last_affected?: string };

/** Match against OSV event ranges (supports multiple introduced/fixed segments). */
function matchesEcosystemEvents(
  version: string,
  events: Array<{ introduced?: string; fixed?: string; deprecated?: string; latest?: string; last_affected?: string }>,
  ecosystem: string,
): AffectedEventResult {
  const segments = parseEventSegments(events);
  for (const segment of segments) {
    if (!versionInEventSegment(version, segment, ecosystem)) continue;
    const range = buildSegmentRange(segment);
    return { isAffected: true, range };
  }
  return { isAffected: false };
}

/** Build a human-readable range string from an event segment */
function buildSegmentRange(segment: EventSegment): string {
  if (segment.last_affected !== null) {
    return `${segment.introduced}-${segment.last_affected}`;
  }
  const suffix = segment.fixed !== null ? `<${segment.fixed}` : "+";
  return `${segment.introduced}${suffix}`;
}

function compareVersionParts(a: number[], b: number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = (a[i] || 0) - (b[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// ─── Semver ─────────────────────────────────────────────────

/**
 * Semver range matcher for patterns like ">=1.0,<2.0" or ">=1.0 <2.0".
 * Unknown / unsupported operators fail closed (not vulnerable) to avoid false positives.
 */
interface SemverParts {
  nums: number[];
  pre: string | null;
}

function parseSemver(version: string): SemverParts {
  const [core, pre] = version.split("-", 2);
  const nums = core.split(".").filter(s => s.length > 0).map(s => {
    const n = Number.parseInt(s, 10);
    return Number.isNaN(n) ? 0 : n;
  });
  return { nums, pre: pre ?? null };
}

/** Component compare. A prerelease is older than the same release. */
function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  const core = compareVersionParts(pa.nums, pb.nums);
  if (core !== 0) return core;
  if (pa.pre === null && pb.pre === null) return 0;
  if (pa.pre === null) return 1;
  if (pb.pre === null) return -1;
  return comparePrerelease(pa.pre, pb.pre);
}

/** Semver prerelease: numeric ids compare as numbers, so alpha.10 > alpha.2. */
function comparePrerelease(a: string, b: string): number {
  const as = a.split(".");
  const bs = b.split(".");
  for (let i = 0; i < Math.max(as.length, bs.length); i++) {
    const c = comparePrereleaseId(as[i], bs[i]);
    if (c !== null) return c;
  }
  return 0;
}

/** Compare one prerelease identifier. Numeric ids sort before alphanumeric ones. */
function comparePrereleaseId(left: string | undefined, right: string | undefined): number | null {
  if (left === undefined) return -1;
  if (right === undefined) return 1;
  const leftNum = /^\d+$/.test(left);
  const rightNum = /^\d+$/.test(right);
  if (leftNum && rightNum) {
    const diff = Number(left) - Number(right);
    if (diff !== 0) return diff;
    return null;
  }
  if (leftNum) return -1;
  if (rightNum) return 1;
  if (left < right) return -1;
  if (left > right) return 1;
  return null;
}

export function matchesSemverRange(version: string, range: string): boolean {
  const constraints = range.split(/[, ]+/).filter(Boolean);
  if (constraints.length === 0) return false;

  for (const constraint of constraints) {
    const result = checkSemverConstraint(constraint, version);
    if (result === null) return false; // unparseable → fail closed
    if (!result) return false;
  }

  return true;
}

/**
 * Check a single semver constraint.
 * Returns null when the constraint cannot be parsed (caller must fail closed).
 */
function checkSemverConstraint(constraint: string, version: string): boolean | null {
  const m = /^(>=|<=|>|<|=)(\d+(?:\.\d+)*)/.exec(constraint);
  if (!m) return null;
  const cmp = compareSemver(version, m[2]);
  switch (m[1]) {
    case ">=": return cmp >= 0;
    case "<=": return cmp <= 0;
    case ">": return cmp > 0;
    case "<": return cmp < 0;
    case "=": return cmp === 0;
    default: return null;
  }
}

const CVSS_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const CVSS_AC: Record<string, number> = { L: 0.77, H: 0.44 };
const CVSS_UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CVSS_CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

/** CVSS v3 roundup to one decimal, per the spec (not banker's round). */
function cvssRoundup(input: number): number {
  const scaled = Math.round(input * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

function cvssPrivileges(pr: string, scopeChanged: boolean): number | undefined {
  if (pr === "N") return 0.85;
  if (pr === "L") return scopeChanged ? 0.68 : 0.62;
  if (pr === "H") return scopeChanged ? 0.5 : 0.27;
  return undefined;
}

/** Base score for a CVSS:3.0 or CVSS:3.1 vector. Null when the vector is incomplete. */
function cvssV3BaseScore(vector: string): number | null {
  if (!vector.startsWith("CVSS:3.")) return null;
  const metrics = new Map<string, string>();
  for (const part of vector.split("/").slice(1)) {
    const [key, value] = part.split(":");
    if (key && value) metrics.set(key, value);
  }
  const av = CVSS_AV[metrics.get("AV") ?? ""];
  const ac = CVSS_AC[metrics.get("AC") ?? ""];
  const ui = CVSS_UI[metrics.get("UI") ?? ""];
  const c = CVSS_CIA[metrics.get("C") ?? ""];
  const i = CVSS_CIA[metrics.get("I") ?? ""];
  const a = CVSS_CIA[metrics.get("A") ?? ""];
  const scope = metrics.get("S");
  if (av === undefined || ac === undefined || ui === undefined || c === undefined || i === undefined || a === undefined) return null;
  if (scope !== "U" && scope !== "C") return null;
  const scopeChanged = scope === "C";
  const pr = cvssPrivileges(metrics.get("PR") ?? "", scopeChanged);
  if (pr === undefined) return null;

  const isc = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    : 6.42 * isc;
  if (impact <= 0) return 0;
  const exploit = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged ? Math.min(1.08 * (impact + exploit), 10) : Math.min(impact + exploit, 10);
  return cvssRoundup(raw);
}

function severityScore(sev: { type?: string; score?: string }): number | null {
  const raw = sev.score?.trim();
  if (!raw) return null;
  const type = sev.type ?? "";
  const v3 = type === "CVSS_V3" || type === "CVSS_V3_1" || type.startsWith("CVSS:3.");
  if (/^\d/.test(raw)) {
    const numeric = Number.parseFloat(raw);
    return Number.isNaN(numeric) ? null : numeric;
  }
  if (v3 || raw.startsWith("CVSS:3.")) return cvssV3BaseScore(raw);
  return null;
}

/** Extract severity level from OSV entry's severity array */
function extractSeverity(entry: any): Finding["severity"] {
  let maxScore = 0;
  let severity: Finding["severity"] = "UNKNOWN";

  for (const sev of entry.severity || []) {
    const score = severityScore(sev);
    if (score === null || score <= maxScore) continue;
    maxScore = score;
    if (score >= 9.0) severity = "CRITICAL";
    else if (score >= 7.0) severity = "HIGH";
    else if (score >= 4.0) severity = "MODERATE";
    else severity = "LOW";
  }

  return severity;
}

/** Collect fixed versions from OSV entry */
function isVersionLike(value: string): boolean {
  const v = value.trim();
  if (!/^\d/.test(v)) return false;
  if (/^[\da-f]{8,}$/i.test(v)) return false;
  return true;
}

function affectedPackageMatches(advName: string, packageName: string, ecosystem: string): boolean {
  if (!advName) return true;
  const eco = ecosystem.toLowerCase();
  const advNorm = eco === "pypi" ? normalizePyPIName(advName) : advName.toLowerCase();
  const pkgNorm = eco === "pypi" ? normalizePyPIName(packageName) : packageName.toLowerCase();
  return advNorm === pkgNorm;
}

function collectFixedVersions(entry: any, packageName: string, ecosystem: string): string[] {
  const fixedSet = new Set<string>();

  for (const affected of entry.affected || []) {
    const advName = affected.package?.name ?? "";
    if (!affectedPackageMatches(advName, packageName, ecosystem)) continue;
    collectFromRanges(fixedSet, affected.ranges);
    collectFromDefaultFormat(fixedSet, affected.default);
  }

  return [...fixedSet].sort((a, b) => a.localeCompare(b));
}

/** Collect fixed versions from ECOSYSTEM event-based ranges */
function collectFromRanges(fixedSet: Set<string>, ranges: unknown[]) {
  for (const r of ranges || []) {
    collectExtractedEvents(fixedSet, r);
    collectEventFixes(fixedSet, r);
    collectFromRepresentations(fixedSet, (r as { representations?: Array<{ range?: string }> }).representations);
  }
}

/** Collect fixed versions from database-specific extracted_events */
function collectExtractedEvents(fixedSet: Set<string>, r: unknown) {
  const extracted = (r as { database_specific?: { extracted_events?: Array<{ fixed?: string }> } }).database_specific?.extracted_events;
  if (!Array.isArray(extracted)) return;
  for (const ev of extracted) {
    if (ev.fixed && isVersionLike(String(ev.fixed))) fixedSet.add(String(ev.fixed));
  }
}

/** Collect fixed versions from standard OSV events array */
function collectEventFixes(fixedSet: Set<string>, r: unknown) {
  const events = (r as { events?: Array<{ fixed?: string; last_affected?: string }> }).events || [];
  for (const ev of events) {
    if (ev.fixed && isVersionLike(String(ev.fixed))) fixedSet.add(String(ev.fixed));
  }
}

/** Extract fixed versions from representation-level ranges */
function collectFromRepresentations(fixedSet: Set<string>, representations: Array<{ range?: string }> | undefined) {
  for (const rep of representations || []) {
    if (!rep.range) continue;
    const rangeStr = String(rep.range);
    addFixedFromRange(fixedSet, rangeStr);
  }
}

/** Try to extract a fixed version from a range string */
function addFixedFromRange(fixedSet: Set<string>, rangeStr: string) {
  // Maven intervals: only an exclusive upper bound `)` is a fixed version.
  // `[1.0,1.9]` still includes 1.9, so 1.9 is not a fix.
  const intervals = splitMavenRangeIntervals(rangeStr.trim());
  if (intervals.length > 0) {
    for (const interval of intervals) {
      const hi = exclusiveMavenUpperBound(interval);
      if (hi) fixedSet.add(hi);
    }
    return;
  }
  // Constraint style: "<1.2.13" — exclusive upper bound
  const ltMatch = /<\s*(\d[^,\s\]]*)/.exec(rangeStr);
  if (ltMatch) fixedSet.add(ltMatch[1].trim());
}

/** Upper version of one bracketed Maven interval, only when the bound is exclusive. */
function exclusiveMavenUpperBound(interval: string): string | null {
  const match = /^([[(])([^,]*),([^)\]]*)([)\]])$/.exec(interval);
  if (match?.[4] !== ")") return null;
  const hi = match[3].trim();
  return hi === "" ? null : hi;
}

/** Collect from OSV default format (state-based version lists) */
function collectFromDefaultFormat(fixedSet: Set<string>, defaults: Array<{ state?: string; versions?: string[] }> | undefined) {
  for (const def of defaults || []) {
    if (def.state === "version-active") continue;
    for (const v of def.versions || []) {
      fixedSet.add(v);
    }
  }
}

/** Range shape needed for introduced/fixed event collection. */
interface OsvRangeLike {
  events?: Array<{ introduced?: string; fixed?: string }>;
  database_specific?: { extracted_events?: Array<{ introduced?: string; fixed?: string }> };
}

/** Affected block shape needed for release-line fix collection. */
interface OsvAffectedBlockLike {
  package?: { name?: string };
  ranges?: OsvRangeLike[];
}

/** Collect introduced versions from an OSV entry (same-package blocks only) */
function collectIntroducedVersions(entry: { affected?: OsvAffectedBlockLike[] }, packageName: string, ecosystem: string): string[] {
  const set = new Set<string>();

  for (const affected of entry.affected || []) {
    if (!affectedPackageMatches(affected.package?.name ?? "", packageName, ecosystem)) continue;
    for (const r of affected.ranges || []) collectIntroducedFromRange(set, r);
  }

  return [...set];
}

/** Add introduced versions from one range's events and extracted_events lists. */
function collectIntroducedFromRange(set: Set<string>, range: OsvRangeLike): void {
  addIntroducedEvents(set, range.events);
  addIntroducedEvents(set, range.database_specific?.extracted_events);
}

/** Add version-like `introduced` values from an OSV event list. */
function addIntroducedEvents(set: Set<string>, events: Array<{ introduced?: string }> | undefined): void {
  for (const ev of events || []) {
    if (ev.introduced && isVersionLike(String(ev.introduced))) set.add(String(ev.introduced));
  }
}

/** Two versions are on the same release line when their major.minor components match. */
function sameReleaseLine(a: string, b: string): boolean {
  const line = (v: string) => /^(\d+)(?:\.(\d+))?/.exec(v);
  const la = line(a);
  const lb = line(b);
  if (!la || !lb) return false;
  return la[1] === lb[1] && (la[2] ?? "0") === (lb[2] ?? "0");
}

/**
 * A version at or above a fixed version on its own release line is patched, even when
 * another range's window numerically contains it (parallel Maven backport lines).
 * A re-introduction — any introduced event above that fix — invalidates the exclusion.
 */
function isPatchedByParallelLineFix(version: string, entry: { affected?: OsvAffectedBlockLike[] }, packageName: string, ecosystem: string): boolean {
  const fixedVersions = collectFixedVersions(entry, packageName, ecosystem);
  if (fixedVersions.length === 0) return false;
  const introduced = collectIntroducedVersions(entry, packageName, ecosystem);

  for (const fixed of fixedVersions) {
    if (comparePackageVersion(version, fixed, ecosystem) < 0) continue;
    if (!sameReleaseLine(version, fixed)) continue;
    if (introduced.some((i) => comparePackageVersion(i, fixed, ecosystem) > 0)) continue;
    return true;
  }
  return false;
}

/** Extract reference URLs from OSV entry */
function extractReferences(entry: any): string[] {
  const urls: string[] = [];

  if (entry.links) {
    for (const link of entry.links) {
      if (link.url) urls.push(link.url);
    }
  }

  return urls.filter(Boolean);
}

/** Deduplicate findings — one finding per distinct vulnerability × package.
 *  The same vulnerability may appear under multiple database IDs (e.g. CVE-... and GHSA-...);
 *  merge those, but never collapse distinct vulnerabilities that merely share a package. */
function deduplicate(findings: Finding[]): Finding[] {
  const out: Finding[] = [];

  for (const f of findings) {
    const dup = out.find(
      e => e.packageName === f.packageName &&
           e.ecosystem === f.ecosystem &&
           (e.id === f.id || e.aliases.includes(f.id) || f.aliases.includes(e.id)),
    );
    if (!dup) {
      out.push(f);
      continue;
    }
    mergeFinding(dup, f);
  }

  return out;
}

/** Merge two findings — keep higher severity, union fixed versions and aliases */
function mergeFinding(existing: Finding, candidate: Finding) {
  if (SeverityOrder[candidate.severity] > SeverityOrder[existing.severity]) {
    existing.severity = candidate.severity;
  }
  for (const v of candidate.fixedVersions) {
    if (!existing.fixedVersions.includes(v)) {
      existing.fixedVersions.push(v);
    }
  }
  for (const a of candidate.aliases) {
    if (!existing.aliases.includes(a)) {
      existing.aliases.push(a);
    }
  }
}
