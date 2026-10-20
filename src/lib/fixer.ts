/**
 * Fixer — Build deterministic remediation plans from scan findings.
 * No LLM involved: fixed versions come straight from OSV advisory data.
 *
 * For each vulnerable package we pick the MINIMAL version that satisfies
 * every finding against that package (a version lower than any fix would
 * leave at least one CVE open).
 */
import type { Finding, AdvisoryEntry } from "./types.ts";
import { comparePackageVersion, entryAffectsPackage } from "./matcher.ts";
import { isPreReleaseOrSnapshot } from "./repo-metadata.ts";
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
  /** Inclusive last-affected version when OSV has no fixed version. */
  lastAffected?: string;
  /** True when this fix moves to an OLDER release (downgrade out of the affected window). */
  isDowngrade?: boolean;
  /** Exclusive lower bound of the vulnerable window across all findings for this package (minimum introduced); undefined when safety cannot be proven. */
  introduced?: string;
  /** Computed downgrade target while the candidate is still unfixable (proposal only, not applied). */
  downgradeTarget?: string;
  /** Set when no GA release fixes the findings but pre-releases do — names that pre-release fix. */
  preReleaseOnlyFix?: string;
}

export interface FixPlan {
  /** Packages with a known fix version. */
  fixable: FixCandidate[];
  /** Packages where OSV data has no usable fixed version. */
  unfixable: FixCandidate[];
  /** Package coordinate renames (Maven group:artifact or npm/pypi/crate name moves). */
  renames: FixCandidate[];
  /** Downgrade-only fixes (no forward fix exists); applied only with --allow-downgrades. */
  downgrades: FixCandidate[];
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
 * Minimal GA fixed version for a single finding that is strictly greater than the
 * installed version. Pre-release fixes (SNAPSHOT, milestone, RC, alpha/beta, Java
 * build) are never targets — a package whose only fix is pre-release goes to the
 * unfixable path with its pre-release fix named. Prefers same-major; cross-major
 * targets are returned too — the CLI major gate (--allow-major / prompt) enforces consent.
 */
function minimalFixForFinding(finding: Finding): string | null {
  const installed = finding.installedVersion;
  const eco = finding.ecosystem;
  const candidates = (finding.fixedVersions || [])
    .filter(v => !isPreReleaseOrSnapshot(v))
    .filter(v => cmp(v, installed, eco) > 0)
    .sort((a, b) => cmp(a, b, eco));

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

  return { fixable: remainingFixable, unfixable: remainingUnfixable, renames, downgrades: [] };
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
    lastAffected: highestLastAffected(pkgFindings),
    introduced: lowestIntroduced(pkgFindings),
    preReleaseOnlyFix: target === null ? preReleaseOnlyFix(pkgFindings) : undefined,
  };
}

/** Highest inclusive last-affected bound among findings that have one. */
function highestLastAffected(findings: Finding[]): string | undefined {
  let best: string | undefined;
  const eco = findings[0].ecosystem;
  for (const finding of findings) {
    if (!finding.lastAffected) continue;
    if (!best || cmp(finding.lastAffected, best, eco) > 0) best = finding.lastAffected;
  }
  return best;
}

/**
 * Strictly-lower safe boundary for downgrades: the minimum `introduced` across all findings
 * for the package. Undefined when any finding lacks an introduced bound — a release below
 * that finding's window cannot be proven safe, so no downgrade may be proposed.
 */
function lowestIntroduced(findings: Finding[]): string | undefined {
  let best: string | undefined;
  const eco = findings[0].ecosystem;
  for (const finding of findings) {
    if (!finding.introduced) return undefined;
    if (best === undefined || cmp(finding.introduced, best, eco) < 0) best = finding.introduced;
  }
  return best;
}

/**
 * When no GA release fixes a package's findings but pre-releases do, the smallest such
 * pre-release fix — named in the report so the manual decision is informed.
 */
function preReleaseOnlyFix(findings: Finding[]): string | undefined {
  let best: string | undefined;
  const eco = findings[0].ecosystem;
  for (const f of findings) {
    for (const v of f.fixedVersions ?? []) {
      if (!isPreReleaseOrSnapshot(v) || cmp(v, f.installedVersion, eco) <= 0) continue;
      if (best === undefined || cmp(v, best, eco) < 0) best = v;
    }
  }
  return best;
}

/**
 * A published version strictly after `lastAffected` is the fix when OSV has no `fixed` event.
 * `lastAffected` itself stays vulnerable and is never the target.
 */
export function withNextFixVersion(candidate: FixCandidate, nextVersion: string | null): FixCandidate | null {
  if (candidate.targetVersion || !candidate.lastAffected || !nextVersion) return null;
  const eco = candidate.ecosystem || "maven";
  if (cmp(nextVersion, candidate.lastAffected, eco) <= 0) return null;
  return {
    ...candidate,
    targetVersion: nextVersion,
    isMajor: majorOf(nextVersion) !== majorOf(candidate.installedVersion),
  };
}

/**
 * A published release strictly below the advisory's introduced bound fixes the finding by
 * moving out of the affected window. The boundary itself stays vulnerable and is never the
 * target, and the release must also be strictly older than what is installed.
 */
export function withDowngradeVersion(candidate: FixCandidate, previousVersion: string | null): FixCandidate | null {
  if (candidate.targetVersion || !candidate.introduced || !previousVersion) return null;
  const eco = candidate.ecosystem || "maven";
  if (cmp(previousVersion, candidate.introduced, eco) >= 0) return null;
  if (cmp(previousVersion, candidate.installedVersion, eco) >= 0) return null;
  return {
    ...candidate,
    targetVersion: previousVersion,
    isMajor: majorOf(previousVersion) !== majorOf(candidate.installedVersion),
    isDowngrade: true,
  };
}

/**
 * First GA release walking outward from `installed` (ascending for "up", descending for
 * "down") that `isUnsafe` does not flag. Pre-releases are never targets. Null when no
 * published GA in that direction escapes every affected window — the package is
 * unsatisfiable in that direction.
 */
export function pickSafeEscapeVersion(
  versions: string[],
  installed: string,
  direction: "up" | "down",
  ecosystem: string,
  isUnsafe: (version: string) => boolean,
): string | null {
  const ga = versions.filter(v => !isPreReleaseOrSnapshot(v));
  if (direction === "up") {
    const above = ga.filter(v => cmp(v, installed, ecosystem) > 0).sort((a, b) => cmp(a, b, ecosystem));
    for (const v of above) if (!isUnsafe(v)) return v;
    return null;
  }
  const below = ga.filter(v => cmp(v, installed, ecosystem) < 0).sort((a, b) => cmp(b, a, ecosystem));
  for (const v of below) if (!isUnsafe(v)) return v;
  return null;
}

/** Advisory entries carrying an affected block for this package in this ecosystem — the full window set a proposed target must escape. */
export function packageAdvisoryEntries(advisories: AdvisoryEntry[], packageName: string, ecosystem: string): AdvisoryEntry[] {
  return advisories.filter(a => entryAffectsPackage(a, packageName, ecosystem));
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
