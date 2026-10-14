/**
 * Fixer — Build deterministic remediation plans from scan findings.
 * No LLM involved: fixed versions come straight from OSV advisory data.
 *
 * For each vulnerable package we pick the MINIMAL version that satisfies
 * every finding against that package (a version lower than any fix would
 * leave at least one CVE open).
 */
import type { Finding, AdvisoryEntry } from "./types.ts";
import { comparePackageVersion } from "./matcher.ts";
import { detectMavenRenames } from "./maven-renames.ts";
import { detectAllPackageRenames } from "./package-renames.ts";

/** A single planned version bump for one package. */
export interface FixCandidate {
  packageName: string;
  installedVersion: string;
  /** Minimal version that fixes all findings, or null if unfixable. */
  targetVersion: string | null;
  /** True when the bump crosses a major version boundary. */
  isMajor: boolean;
  /** Advisory IDs (GHSA/CVE) addressed by this bump. */
  findingIds: string[];
  /** Highest severity among the findings for this package. */
  severity: Finding["severity"];
  /** Maven rename: new group:artifact when coordinates moved. */
  renameTo?: string;
  /** Ecosystem for package renames (npm, pypi, crates.io, maven). */
  ecosystem?: string;
  /** True when this fix is a coordinate rename, not an in-place bump. */
  isRename?: boolean;
  /** True for preemptive --latest bumps (no advisory finding behind them). */
  latest?: boolean;
}

export interface FixPlan {
  /** Packages with a known fix version. */
  fixable: FixCandidate[];
  /** Packages where OSV data has no usable fixed version. */
  unfixable: FixCandidate[];
  /** Package coordinate renames (Maven group:artifact or npm/pypi/crate name moves). */
  renames: FixCandidate[];
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/** Group key — same name in different ecosystems must not merge. */
export function findingPackageKey(f: Pick<Finding, "ecosystem" | "packageName">): string {
  return `${f.ecosystem}:${f.packageName}`;
}

function candidateKey(c: Pick<FixCandidate, "ecosystem" | "packageName">): string {
  return `${c.ecosystem || ""}:${c.packageName}`;
}

/** First numeric segment of a version string ("1.2.13" -> 1). */
export function majorOf(version: string): number {
  const m = /^(\d+)/.exec(String(version).replace(/^v/, ""));
  return m ? Number.parseInt(m[1], 10) : 0;
}

function cmp(a: string, b: string, ecosystem: string): number {
  return comparePackageVersion(a, b, ecosystem);
}

/**
 * Minimal fixed version for a single finding that is strictly greater
 * than the installed version. Prefers same-major; cross-major targets are
 * returned too — the CLI major gate (--allow-major / prompt) enforces consent.
 */
function minimalFixForFinding(finding: Finding): string | null {
  const installed = finding.installedVersion;
  const eco = finding.ecosystem;
  const candidates = (finding.fixedVersions || [])
    .filter(v => cmp(v, installed, eco) > 0)
    .sort((a, b) => cmp(a, b, eco));
  if (candidates.length === 0) return null;

  const installedMajor = majorOf(installed);
  const sameMajor = candidates.filter(v => majorOf(v) === installedMajor);
  if (sameMajor.length > 0) return sameMajor[0];

  return candidates[0];
}

/**
 * Build a fix plan from scan findings.
 * Findings are grouped by ecosystem+package; the target version is the maximum of the
 * per-finding minimal fixes (so every advisory is satisfied at once).
 */
export function buildFixPlan(findings: Finding[], advisories: AdvisoryEntry[] = []): FixPlan {
  const byPackage = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = findingPackageKey(f);
    const list = byPackage.get(key);
    if (list) list.push(f);
    else byPackage.set(key, [f]);
  }

  const fixable: FixCandidate[] = [];
  const unfixable: FixCandidate[] = [];

  for (const [, pkgFindings] of byPackage) {
    const candidate = buildCandidate(pkgFindings);
    classifyCandidate(fixable, unfixable, candidate);
  }

  // Highest severity first, stable within severity by package name.
  const bySeverityDesc = (a: FixCandidate, b: FixCandidate) =>
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    a.packageName.localeCompare(b.packageName);
  fixable.sort(bySeverityDesc);
  unfixable.sort(bySeverityDesc);

  const mavenRenames = detectMavenRenames(findings, advisories).map(r => ({
    packageName: r.fromPackage,
    installedVersion: findings.find(f => f.packageName === r.fromPackage)?.installedVersion || "",
    targetVersion: r.targetVersion,
    isMajor: majorOf(r.targetVersion) !== majorOf(
      findings.find(f => f.packageName === r.fromPackage)?.installedVersion || "0",
    ),
    findingIds: [...new Set(r.findingIds)],
    severity: r.severity,
    renameTo: r.toPackage,
    ecosystem: "maven",
    isRename: true,
  }));

  const packageRenames = detectAllPackageRenames(findings, advisories).map(r => ({
    packageName: r.fromPackage,
    installedVersion: findings.find(
      f => f.packageName === r.fromPackage && f.ecosystem === r.ecosystem,
    )?.installedVersion || findings.find(f => f.packageName === r.fromPackage)?.installedVersion || "",
    targetVersion: r.targetVersion,
    isMajor: majorOf(r.targetVersion) !== majorOf(
      findings.find(f => f.packageName === r.fromPackage)?.installedVersion || "0",
    ),
    findingIds: [...new Set(r.findingIds)],
    severity: r.severity,
    renameTo: r.toPackage,
    ecosystem: r.ecosystem,
    isRename: true,
  }));

  const renames: FixCandidate[] = [...mavenRenames, ...packageRenames];

  const renameFrom = new Set(renames.map(candidateKey));
  const remainingFixable = fixable.filter(f => !renameFrom.has(candidateKey(f)));
  const remainingUnfixable = unfixable.filter(u => !renameFrom.has(candidateKey(u)));

  return { fixable: remainingFixable, unfixable: remainingUnfixable, renames };
}

/** Build a single FixCandidate from grouped findings for one ecosystem+package */
function buildCandidate(pkgFindings: Finding[]): FixCandidate {
  const packageName = pkgFindings[0].packageName;
  const ecosystem = pkgFindings[0].ecosystem;
  const installedVersion = pkgFindings[0].installedVersion;
  const findingIds = [...new Set(pkgFindings.map(f => f.id))];
  const severity = reduceMaxSeverity(pkgFindings);
  const target = computeTargetVersion(pkgFindings);

  return {
    packageName,
    installedVersion,
    targetVersion: target,
    isMajor: target !== null && majorOf(target) !== majorOf(installedVersion),
    findingIds,
    severity,
    ecosystem,
  };
}

/** Compute the highest severity across findings */
function reduceMaxSeverity(findings: Finding[]): Finding["severity"] {
  return findings.reduce<Finding["severity"]>(
    (max, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[max] ? f.severity : max),
    "UNKNOWN",
  );
}

/** Find the max fix version across all findings (cross-major included; gated by --allow-major) */
function computeTargetVersion(findings: Finding[]): string | null {
  let target: string | null = null;
  const eco = findings[0].ecosystem;
  for (const f of findings) {
    const fix = minimalFixForFinding(f);
    if (!fix) continue;
    if (target === null || cmp(fix, target, eco) > 0) {
      target = fix;
    }
  }
  return target;
}

/** Classify a candidate as fixable, unfixable, or already-satisfied */
function classifyCandidate(
  fixable: FixCandidate[],
  unfixable: FixCandidate[],
  candidate: FixCandidate,
): void {
  if (candidate.targetVersion === null) {
    unfixable.push(candidate);
  } else if (
    cmp(
      candidate.installedVersion,
      candidate.targetVersion,
      candidate.ecosystem || "maven",
    ) >= 0
  ) {
    // Already at or past fix — skip (stale OSV noise)
  } else {
    fixable.push(candidate);
  }
}
