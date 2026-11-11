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
  /** Best fix on the installed major line; set for cross-major candidates as the family-clamp fallback. */
  sameMajorTarget?: string;
  /** Set when the co-versioned-family guard altered this candidate (clamped to the same line, or demoted to unfixable). */
  familyClamped?: string;
  /** Set when a coherent whole-family migration re-targeted this candidate (all family members pinned to one version). */
  familyMigrated?: string;
  /** Set when a consumer-variant swap (e.g. wiremock -> wiremock-jetty12) replaces this coordinate; same version, no findings of its own. */
  consumerVariant?: boolean;
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

/** Highest severity first, stable within severity by package name. */
const bySeverityDesc = (a: FixCandidate, b: FixCandidate) =>
  SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
  a.packageName.localeCompare(b.packageName);

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

/** GA fixed versions strictly above the installed version, sorted ascending. */
function gaCandidatesAboveInstalled(finding: Finding): string[] {
  const installed = finding.installedVersion;
  const eco = finding.ecosystem;
  return (finding.fixedVersions || [])
    .filter(v => !isPreReleaseOrSnapshot(v))
    .filter(v => cmp(v, installed, eco) > 0)
    .sort((a, b) => cmp(a, b, eco));
}

/**
 * Minimal GA fixed version for a single finding that is strictly greater than the
 * installed version. Pre-release fixes (SNAPSHOT, milestone, RC, alpha/beta, Java
 * build) are never targets — a package whose only fix is pre-release goes to the
 * unfixable path with its pre-release fix named. Prefers same-major; cross-major
 * targets are returned too — the CLI major gate (--allow-major / prompt) enforces consent.
 */
function minimalFixForFinding(finding: Finding): string | null {
  const candidates = gaCandidatesAboveInstalled(finding);
  if (candidates.length === 0) return null;

  const installedMajor = majorOf(finding.installedVersion);
  const sameMajor = candidates.filter(v => majorOf(v) === installedMajor);
  if (sameMajor.length > 0) return sameMajor[0];

  return candidates[0];
}

/** Best fix on the installed major line: max GA candidate of that major strictly above installed. */
function sameMajorFixForFinding(finding: Finding): string | undefined {
  const installedMajor = majorOf(finding.installedVersion);
  const sameMajor = gaCandidatesAboveInstalled(finding).filter(v => majorOf(v) === installedMajor);
  return sameMajor.length > 0 ? sameMajor[sameMajor.length - 1] : undefined;
}

/** Max same-major fix across findings — the fallback target when a cross-major bump is clamped. */
function sameMajorTarget(findings: Finding[]): string | undefined {
  let best: string | undefined;
  const eco = findings[0].ecosystem;
  for (const f of findings) {
    const fix = sameMajorFixForFinding(f);
    if (!fix) continue;
    if (best === undefined || cmp(fix, best, eco) > 0) best = fix;
  }
  return best;
}

/**
 * Co-versioned families: packages that must stay on one major line together on a classpath.
 * Explicit table — no generic prefix inference, which would false-positive on unrelated
 * groups (e.g. org.apache.commons*).
 */
export const COVERSIONED_FAMILIES: ReadonlyArray<{ name: string; prefixes: readonly string[] }> = [
  { name: "jetty", prefixes: ["org.eclipse.jetty"] },
  { name: "netty", prefixes: ["io.netty"] },
  { name: "vertx", prefixes: ["io.vertx"] },
  { name: "jackson", prefixes: ["com.fasterxml.jackson"] },
  { name: "jaxb", prefixes: ["org.glassfish.jaxb"] },
];

/** Family for a package (Maven "group:artifact"; subgroups match via dot boundary); longest prefix wins. */
export function familyOf(packageName: string): { name: string; prefix: string } | null {
  const group = packageName.includes(":") ? packageName.slice(0, packageName.indexOf(":")) : packageName;
  let best: { name: string; prefix: string } | null = null;
  for (const fam of COVERSIONED_FAMILIES) {
    for (const prefix of fam.prefixes) {
      if ((group === prefix || group.startsWith(prefix + ".")) && (!best || prefix.length > best.prefix.length)) {
        best = { name: fam.name, prefix };
      }
    }
  }
  return best;
}

/**
 * Co-versioned-family consistency guard. A cross-major target is only allowed when every
 * classpath sibling of the same family also moves to that major in this pass; otherwise the
 * bump would split the family (e.g. jetty-http 12.x next to jetty-server 11.x) and break the
 * build. Clamps to the best same-line fix, or demotes to unfixable when no same-line fix exists.
 */
export function applyFamilyConsistency(
  plan: FixPlan,
  classpath: ReadonlyArray<Pick<Finding, "packageName" | "installedVersion" | "ecosystem">>,
): FixPlan {
  const plannedMajor = new Map<string, number>();
  for (const c of plan.fixable) {
    if (c.targetVersion !== null) plannedMajor.set(c.packageName, majorOf(c.targetVersion));
  }
  const renamedAway = new Set(plan.renames.map(r => r.packageName));

  const fixable: FixCandidate[] = [];
  const unfixable = plan.unfixable.slice();
  for (const c of plan.fixable) {
    if (c.ecosystem === "maven" && c.isMajor && c.targetVersion !== null) {
      const fam = familyOf(c.packageName);
      if (fam) {
        const siblings = classpath.filter(
          p => p.ecosystem === "maven" && p.packageName !== c.packageName && familyOf(p.packageName)?.name === fam.name,
        );
        if (siblings.length > 0) {
          const targetMajor = majorOf(c.targetVersion);
          const split = siblings.some(s => plannedMajor.get(s.packageName) !== targetMajor && !renamedAway.has(s.packageName));
          if (split) {
            if (c.sameMajorTarget !== undefined) {
              fixable.push({
                ...c,
                targetVersion: c.sameMajorTarget,
                isMajor: false,
                familyClamped: `clamped to ${c.sameMajorTarget}: cross-major ${c.targetVersion} would split family '${fam.name}' (siblings on ${majorOf(c.installedVersion)}.x not moving in this pass)`,
              });
              continue;
            }
            unfixable.push({
              ...c,
              targetVersion: null,
              isMajor: false,
              familyClamped: `no fix on installed line; cross-major ${c.targetVersion} would split family '${fam.name}' (siblings not moving)`,
            });
            continue;
          }
        }
      }
    }
    fixable.push(c);
  }

  fixable.sort(bySeverityDesc);
  unfixable.sort(bySeverityDesc);
  return { ...plan, fixable, unfixable };
}

/** A co-versioned family on the classpath that needs a coherent whole-family move decision. */
export interface FamilyMigration {
  /** Family name from COVERSIONED_FAMILIES ("jetty", "netty", ...). */
  familyName: string;
  /** Every classpath member of the family — all must be pinned to one version to keep the family coherent. */
  memberPackages: ReadonlyArray<string>;
  /** Candidate target major lines, ascending, starting at the newest installed line (an in-place pin is tried first). A line qualifies when every member is safe at some published GA version on it. */
  linesToTry: ReadonlyArray<number>;
}

/**
 * Co-versioned families that need a whole-family move decision: Maven families with at least
 * two classpath members and at least one member carrying an active finding. Whether the family
 * is actually stuck (unpublished same-line targets, guard-clamped or demoted candidates) is
 * decided by the caller, which has the published-version lists.
 */
export function planFamilyMigrations(
  classpath: ReadonlyArray<Pick<Finding, "packageName" | "installedVersion" | "ecosystem">>,
  findings: Finding[],
): FamilyMigration[] {
  const affected = new Set(findings.filter(f => f.ecosystem === "maven").map(f => f.packageName));
  const byFamily = new Map<string, Array<Pick<Finding, "packageName" | "installedVersion">>>();
  for (const p of classpath) {
    if (p.ecosystem !== "maven") continue;
    const fam = familyOf(p.packageName);
    if (!fam) continue;
    const members = byFamily.get(fam.name) ?? [];
    members.push({ packageName: p.packageName, installedVersion: p.installedVersion });
    byFamily.set(fam.name, members);
  }

  const out: FamilyMigration[] = [];
  for (const [name, members] of [...byFamily.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (members.length < 2) continue; // no siblings to keep coherent
    if (!members.some(m => affected.has(m.packageName))) continue; // nothing to move for
    const memberSet = new Set(members.map(p => p.packageName));
    const installedMajors = [...new Set(members.map(p => majorOf(p.installedVersion)))];
    const base = Math.max(...installedMajors);
    const lines = new Set<number>([base, base + 1]);
    for (const f of findings) {
      if (!memberSet.has(f.packageName) || f.ecosystem !== "maven") continue;
      for (const v of f.fixedVersions || []) {
        if (isPreReleaseOrSnapshot(v)) continue;
        const m = majorOf(v);
        if (m > base) lines.add(m);
      }
    }
    out.push({ familyName: name, memberPackages: [...memberSet], linesToTry: [...lines].sort((a, b) => a - b) });
  }
  return out;
}

/**
 * Build a fix plan from scan findings.
 * Findings are grouped by ecosystem+package; the target version is the maximum of the
 * per-finding minimal fixes (so every advisory is satisfied at once). When a classpath is
 * supplied, the co-versioned-family consistency guard runs before the rename filter so a
 * cross-major bump can never split its family on the classpath.
 */
export function buildFixPlan(
  findings: Finding[],
  advisories: AdvisoryEntry[] = [],
  classpath?: ReadonlyArray<Pick<Finding, "packageName" | "installedVersion" | "ecosystem">>,
): FixPlan {
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

  let plan: FixPlan = { fixable, unfixable, renames, downgrades: [] };
  if (classpath) plan = applyFamilyConsistency(plan, classpath);

  const renameFrom = new Set(renames.map(candidateKey));
  const remainingFixable = plan.fixable.filter(f => !renameFrom.has(candidateKey(f)));
  const remainingUnfixable = plan.unfixable.filter(u => !renameFrom.has(candidateKey(u)));

  return { fixable: remainingFixable, unfixable: remainingUnfixable, renames, downgrades: plan.downgrades };
}

/** Build a single FixCandidate from grouped findings for one ecosystem+package */
function buildCandidate(pkgFindings: Finding[]): FixCandidate {
  const packageName = pkgFindings[0].packageName;
  const ecosystem = pkgFindings[0].ecosystem;
  const installedVersion = pkgFindings[0].installedVersion;
  const findingIds = [...new Set(pkgFindings.map(f => f.id))];
  const severity = reduceMaxSeverity(pkgFindings);
  const target = computeTargetVersion(pkgFindings);
  const crossMajor = target !== null && majorOf(target) !== majorOf(installedVersion);

  return {
    packageName,
    installedVersion,
    targetVersion: target,
    isMajor: crossMajor,
    findingIds,
    severity,
    ecosystem,
    lastAffected: highestLastAffected(pkgFindings),
    introduced: lowestIntroduced(pkgFindings),
    preReleaseOnlyFix: target === null ? preReleaseOnlyFix(pkgFindings) : undefined,
    sameMajorTarget: crossMajor ? sameMajorTarget(pkgFindings) : undefined,
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
