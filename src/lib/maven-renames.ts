/**
 * Detect Maven coordinate renames from OSV advisory data and known group migrations.
 */
import type { AdvisoryEntry, Finding, PackageRef } from "./types.ts";
import { compareMavenVersion } from "./matcher.ts";

export interface MavenRenameOption {
  fromPackage: string;
  toPackage: string;
  targetVersion: string;
  findingIds: string[];
  severity: Finding["severity"];
}

export interface JavaPackageRule {
  fromPrefix: string;
  toPrefix: string;
  exceptPrefixes?: string[];
}

export interface JavaSourceMigration {
  rules: JavaPackageRule[];
  globs?: string[];
}

export interface SourcePackageRule {
  fromPackage: string;
  toPackage: string;
}

export interface SourceLanguageMigration {
  rules: SourcePackageRule[];
  globs?: string[];
}

export interface SourceMigrationConfig {
  java?: JavaSourceMigration;
  javascript?: SourceLanguageMigration;
  python?: SourceLanguageMigration;
  rust?: SourceLanguageMigration;
  clusters: string[];
}

export interface MigrationCluster {
  key: string;
  maven: Record<string, string>;
  source?: {
    java?: JavaSourceMigration;
  };
  excludeOldCoordinates?: boolean;
  keepCoordinates?: string[];
  removeBomCoords?: string[];
  rejectPins?: string[];
  extraPins?: Array<{ packageName: string; version: string }>;
}

const JACKSON_CLUSTER_KEY = "com.fasterxml.jackson.core|tools.jackson.core";

/** Jackson 3 keeps jackson-annotations on 2.x coords; Java package stays com.fasterxml.jackson.annotation. */
export const JACKSON3_ANNOTATIONS_COORD = "com.fasterxml.jackson.core:jackson-annotations";
export const JACKSON3_ANNOTATIONS_VERSION = "2.21";

export function isJackson3AnnotationsCoord(coord: string): boolean {
  return coord === JACKSON3_ANNOTATIONS_COORD;
}

/** Known coordinate migrations; extend as new group moves appear. */
const MIGRATION_CLUSTERS: MigrationCluster[] = [
  {
    key: JACKSON_CLUSTER_KEY,
    maven: {
      "com.fasterxml.jackson.core:jackson-core": "tools.jackson.core:jackson-core",
      "com.fasterxml.jackson.core:jackson-databind": "tools.jackson.core:jackson-databind",
    },
    source: {
      java: {
        rules: [
          {
            fromPrefix: "com.fasterxml.jackson.datatype.jsr310",
            toPrefix: "tools.jackson.databind.ext.javatime",
          },
          {
            fromPrefix: "com.fasterxml.jackson.datatype.jdk8",
            toPrefix: "tools.jackson.databind.ext.jdk8",
          },
          {
            fromPrefix: "com.fasterxml.jackson",
            toPrefix: "tools.jackson",
            exceptPrefixes: ["com.fasterxml.jackson.annotation"],
          },
        ],
      },
    },
    excludeOldCoordinates: true,
    keepCoordinates: [JACKSON3_ANNOTATIONS_COORD],
    removeBomCoords: ["com.fasterxml.jackson:jackson-bom"],
    rejectPins: ["tools.jackson.core:jackson-annotations"],
    extraPins: [{ packageName: JACKSON3_ANNOTATIONS_COORD, version: JACKSON3_ANNOTATIONS_VERSION }],
  },
];

/** Fallback Maven renames derived from migration clusters. */
const KNOWN_RENAMES: Record<string, string> = Object.fromEntries(
  MIGRATION_CLUSTERS.flatMap(c => Object.entries(c.maven)),
);

export function mavenGroup(coord: string): string {
  return coord.split(":")[0] || "";
}

export function migrationClusterKey(fromPackage: string, toPackage: string): string {
  return `${mavenGroup(fromPackage)}|${mavenGroup(toPackage)}`;
}

/** Group known migrations by old-group -> new-group cluster. */
export function migrationsByCluster(): Map<string, Record<string, string>> {
  const clusters = new Map<string, Record<string, string>>();
  for (const cluster of MIGRATION_CLUSTERS) {
    clusters.set(cluster.key, { ...cluster.maven });
  }
  return clusters;
}

export function migrationClusterForKey(key: string): MigrationCluster | null {
  return MIGRATION_CLUSTERS.find(c => c.key === key) || null;
}

/** Merged apply policy across the migration clusters touched by applied renames. */
export interface RenameApplyPolicy {
  excludeOldCoordinates: boolean;
  keepCoordinates: Set<string>;
  removeBomCoords: string[];
  rejectPins: Set<string>;
  extraPins: Array<{ packageName: string; version: string }>;
  clusterKeys: string[];
}

export function applyPolicyForRenames(renames: Array<{ fromPackage: string; toPackage: string }>): RenameApplyPolicy {
  const seen = new Set<string>();
  const clusters: MigrationCluster[] = [];
  for (const r of renames) {
    const key = migrationClusterKey(r.fromPackage, r.toPackage);
    if (seen.has(key)) continue;
    seen.add(key);
    const cluster = migrationClusterForKey(key);
    if (cluster) clusters.push(cluster);
  }
  return {
    excludeOldCoordinates: clusters.some(c => c.excludeOldCoordinates),
    keepCoordinates: new Set(clusters.flatMap(c => c.keepCoordinates ?? [])),
    removeBomCoords: [...new Set(clusters.flatMap(c => c.removeBomCoords ?? []))],
    rejectPins: new Set(clusters.flatMap(c => c.rejectPins ?? [])),
    extraPins: clusters.flatMap(c => c.extraPins ?? []),
    clusterKeys: clusters.map(c => c.key),
  };
}

/** True when a coordinate stays on its old group per its migration cluster. */
export function isKeptCoordinate(coord: string): boolean {
  return MIGRATION_CLUSTERS.some(c => (c.keepCoordinates ?? []).includes(coord));
}

/** Source rewrite rules for applied renames (null when no cluster or ecosystem rules). */
export function sourceMigrationsForAppliedRenames(
  renames: Array<{ packageName?: string; fromPackage?: string; renameTo?: string; toPackage?: string; ecosystem?: string }>,
): SourceMigrationConfig | null {
  const javaRules: JavaPackageRule[] = [];
  const javaGlobSet = new Set<string>();
  const jsRules: SourcePackageRule[] = [];
  const pyRules: SourcePackageRule[] = [];
  const rustRules: SourcePackageRule[] = [];
  const clusterKeys = new Set<string>();
  let found = false;

  for (const rename of renames) {
    const from = rename.fromPackage || rename.packageName;
    const to = rename.toPackage || rename.renameTo;
    if (!from || !to) continue;

    processSingleRename({ javaRules, javaGlobSet, jsRules, pyRules, rustRules, clusterKeys }, from, to, rename);
    // Track 'found' after processing
    if (javaRules.length > 0 || clusterKeys.size > 0 || jsRules.length > 0 || pyRules.length > 0 || rustRules.length > 0) {
      found = true;
    }
  }

  if (!found) return null;
  const config: SourceMigrationConfig = { clusters: [...clusterKeys] };
  if (javaRules.length > 0) {
    config.java = { rules: javaRules, globs: [...javaGlobSet] };
  }
  if (jsRules.length > 0) {
    config.javascript = {
      rules: jsRules,
      globs: ["**/*.{js,ts,tsx,mjs,cjs,jsx}"],
    };
  }
  if (pyRules.length > 0) {
    config.python = {
      rules: pyRules,
      globs: ["**/*.py"],
    };
  }
  if (rustRules.length > 0) {
    config.rust = {
      rules: rustRules,
      globs: ["**/*.rs"],
    };
  }
  return config;
}

/** Accumulator for rename processing results */
interface RenameAccumulator {
  javaRules: JavaPackageRule[];
  javaGlobSet: Set<string>;
  jsRules: SourcePackageRule[];
  pyRules: SourcePackageRule[];
  rustRules: SourcePackageRule[];
  clusterKeys: Set<string>;
}

/** Process one rename entry — extract Java rules and ecosystem-specific rules */
function processSingleRename(acc: RenameAccumulator, from: string, to: string, rename: { ecosystem?: string }) {
  // Check Java cluster migration
  const key = migrationClusterKey(from, to);
  const meta = migrationClusterForKey(key);
  if (meta?.source?.java) {
    acc.clusterKeys.add(key);
    addJavaRules(acc.javaRules, meta.source.java);
    addJavaGlobs(acc.javaGlobSet, meta.source.java.globs);
  }

  // Check ecosystem-specific rewrites
  const eco = (rename.ecosystem || "").toLowerCase();
  addEcosystemRule(eco, from, to, acc.jsRules, acc.pyRules, acc.rustRules);
}

/** Add Java package rules from a cluster's source config */
function addJavaRules(rules: JavaPackageRule[], java: JavaSourceMigration) {
  for (const rule of java.rules) {
    if (!rules.some(r => r.fromPrefix === rule.fromPrefix)) {
      rules.push(rule);
    }
  }
}

/** Add Java glob patterns */
function addJavaGlobs(globSet: Set<string>, globs: string[] | undefined) {
  const defaultGlobs = globs || ["src/main/java/**/*.java", "src/test/java/**/*.java"];
  for (const glob of defaultGlobs) {
    globSet.add(glob);
  }
}

/** Route ecosystem-specific rename to correct rule list */
function addEcosystemRule(
  eco: string,
  from: string,
  to: string,
  jsRules: SourcePackageRule[],
  pyRules: SourcePackageRule[],
  rustRules: SourcePackageRule[],
) {
  switch (eco) {
    case "npm": pushUniqueRule(jsRules, from, to); break;
    case "pypi": pushUniqueRule(pyRules, from, to); break;
    case "crates.io": pushUniqueRule(rustRules, from, to); break;
  }
}

/** Push a rule only if not already present */
function pushUniqueRule(rules: SourcePackageRule[], from: string, to: string) {
  if (!rules.some(r => r.fromPackage === from && r.toPackage === to)) {
    rules.push({ fromPackage: from, toPackage: to });
  }
}

/** @deprecated Use sourceMigrationsForAppliedRenames */
export function javaRulesForAppliedRenames(
  renames: Array<{ packageName?: string; fromPackage?: string; renameTo?: string; toPackage?: string }>,
): { rules: JavaPackageRule[]; globs: string[] } | null {
  const config = sourceMigrationsForAppliedRenames(renames);
  if (!config?.java) return null;
  return { rules: config.java.rules, globs: config.java.globs || [] };
}

export function clusterForMigration(
  fromPackage: string,
  toPackage: string,
): Record<string, string> | null {
  return migrationsByCluster().get(migrationClusterKey(fromPackage, toPackage)) || null;
}

/** Other coords in the same migration cluster (same group move). */
export function siblingMigrations(fromPackage: string, toPackage: string): string[] {
  const cluster = clusterForMigration(fromPackage, toPackage);
  if (!cluster) return [];
  return Object.keys(cluster).filter(k => k !== fromPackage);
}

export interface RenameBundleItem {
  packageName: string;
  installedVersion: string;
  targetVersion: string | null;
  renameTo?: string;
  findingIds: string[];
  severity: Finding["severity"];
  isMajor: boolean;
  isRename?: boolean;
}

/** When one coord in a migration cluster renames, bundle siblings present on classpath. */
export function expandRenameBundle<T extends RenameBundleItem>(
  renames: T[],
  packages: PackageRef[],
): T[] {
  const out = [...renames];
  const seen = new Set(renames.map(r => r.packageName));

  for (const anchor of renames) {
    if (!anchor.renameTo || !anchor.targetVersion) continue;
    const cluster = clusterForMigration(anchor.packageName, anchor.renameTo);
    if (!cluster) continue;
    expandCluster(out, seen, anchor, cluster, packages);
  }

  return out.sort((a, b) => a.packageName.localeCompare(b.packageName));
}

/** Expand a single cluster into bundled rename items */
function expandCluster<T extends RenameBundleItem>(
  out: T[],
  seen: Set<string>,
  anchor: T,
  cluster: Record<string, string>,
  packages: PackageRef[],
) {
  for (const [fromPackage, toPackage] of Object.entries(cluster)) {
    if (seen.has(fromPackage)) continue;
    if (isJackson3AnnotationsCoord(fromPackage)) continue;
    const pkg = packages.find(p => p.name === fromPackage);
    if (!pkg) continue;

    out.push({
      ...anchor,
      packageName: fromPackage,
      installedVersion: pkg.version,
      targetVersion: anchor.targetVersion,
      renameTo: toPackage,
      isRename: true,
    } as T);
    seen.add(fromPackage);
  }
}

function mavenArtifact(coord: string): string {
  const idx = coord.lastIndexOf(":");
  return idx >= 0 ? coord.slice(idx + 1) : coord;
}

function isVersionLike(value: string): boolean {
  const v = value.trim();
  return /^\d/.test(v) && !/^[0-9a-f]{8,}$/i.test(v);
}

function fixedVersionsForAffected(affected: AdvisoryEntry["affected"][number]): string[] {
  const fixed = new Set<string>();
  for (const r of affected.ranges || []) {
    const range = r as {
      events?: Array<{ fixed?: string }>;
      database_specific?: { extracted_events?: Array<{ fixed?: string }> };
    };
    const events = range.database_specific?.extracted_events?.length
      ? range.database_specific.extracted_events
      : range.events || [];
    for (const ev of events) {
      if (ev.fixed && isVersionLike(String(ev.fixed))) fixed.add(String(ev.fixed));
    }
  }
  return [...fixed].sort((a, b) => compareMavenVersion(a, b));
}

function pickRenameTarget(installed: string, fixes: string[]): string | null {
  if (fixes.length === 0) return null;
  const eligible = fixes.filter(v => compareMavenVersion(v, installed) >= 0);
  if (eligible.length > 0) return eligible[0];
  return fixes.at(-1) ?? null;
}

function advisoriesForFinding(finding: Finding, advisories: AdvisoryEntry[]): AdvisoryEntry[] {
  const ids = new Set([finding.id, ...finding.aliases]);
  return advisories.filter(a =>
    ids.has(a.id) || a.aliases.some(alias => ids.has(alias)),
  );
}

function renameOptionsFromAdvisory(
  finding: Finding,
  advisory: AdvisoryEntry,
): Array<{ toPackage: string; targetVersion: string }> {
  const from = finding.packageName;
  const artifact = mavenArtifact(from);
  const options: Array<{ toPackage: string; targetVersion: string }> = [];

  for (const affected of advisory.affected || []) {
    const name = affected.package?.name || "";
    if (!name || name === from) continue;
    if (mavenArtifact(name) !== artifact) continue;
    if ((affected.package?.ecosystem || "").toLowerCase() !== "maven") continue;

    const fixes = fixedVersionsForAffected(affected);
    const target = pickRenameTarget(finding.installedVersion, fixes);
    if (target) options.push({ toPackage: name, targetVersion: target });
  }

  return options;
}

function sameMajorInPlaceFix(finding: Finding): boolean {
  const installedMajor = Number.parseInt(finding.installedVersion.split(".")[0] || "0", 10);
  return (finding.fixedVersions || []).some(
    v => compareMavenVersion(v, finding.installedVersion) > 0 && majorOf(v) === installedMajor,
  );
}

function majorOf(version: string): number {
  const m = /^(\d+)/.exec(String(version).replace(/^v/, ""));
  return m ? Number.parseInt(m[1], 10) : 0;
}

function crossMajorFixes(finding: Finding): string[] {
  const installedMajor = majorOf(finding.installedVersion);
  return (finding.fixedVersions || [])
    .filter(v => compareMavenVersion(v, finding.installedVersion) > 0)
    .filter(v => majorOf(v) !== installedMajor)
    .sort((a, b) => compareMavenVersion(a, b));
}

function knownRenameOption(finding: Finding): { toPackage: string; targetVersion: string } | null {
  const toPackage = KNOWN_RENAMES[finding.packageName];
  if (!toPackage) return null;

  if (finding.packageName === toPackage) return null;

  const installedMajor = majorOf(finding.installedVersion);
  const cross = crossMajorFixes(finding);

  if (cross.length === 0) return null;

  const crossMajor = majorOf(cross[0]);
  if (installedMajor >= crossMajor) {
    const target = pickRenameTarget(finding.installedVersion, finding.fixedVersions);
    return { toPackage, targetVersion: target || finding.installedVersion };
  }

  return { toPackage, targetVersion: cross[0] };
}

/** Find Maven rename migrations for findings that cannot be fixed in-place. */
export function detectMavenRenames(
  findings: Finding[],
  advisories: AdvisoryEntry[],
): MavenRenameOption[] {
  const results: MavenRenameOption[] = [];
  const seen = new Set<string>();
  const byPackage = groupByPackage(findings);

  for (const finding of findings) {
    if (finding.ecosystem !== "maven") continue;
    if (isJackson3AnnotationsCoord(finding.packageName)) continue;
    if (shouldSkipFinding(finding, byPackage)) continue;

    const candidates = collectCandidates(finding, advisories);
    addResults(results, seen, finding, candidates);
  }

  return results.sort((a, b) => a.fromPackage.localeCompare(b.fromPackage));
}

/** Group Maven findings by package name */
function groupByPackage(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.ecosystem !== "maven") continue;
    const list = map.get(f.packageName);
    if (list) list.push(f);
    else map.set(f.packageName, [f]);
  }
  return map;
}

/** Check if a finding should be skipped (same-major fix available) */
function shouldSkipFinding(
  finding: Finding,
  byPackage: Map<string, Finding[]>,
): boolean {
  const pkgFindings = byPackage.get(finding.packageName) || [finding];
  if (pkgFindings.some(sameMajorInPlaceFix)) return true;
  return sameMajorInPlaceFix(finding);
}

/** Collect all rename candidates for a finding across its advisories */
function collectCandidates(
  finding: Finding,
  advisories: AdvisoryEntry[],
): Map<string, string> {
  const candidates = new Map<string, string>();

  for (const advisory of advisoriesForFinding(finding, advisories)) {
    for (const opt of renameOptionsFromAdvisory(finding, advisory)) {
      const prev = candidates.get(opt.toPackage);
      if (!prev || compareMavenVersion(opt.targetVersion, prev) > 0) {
        candidates.set(opt.toPackage, opt.targetVersion);
      }
    }
  }

  const known = knownRenameOption(finding);
  if (known && !candidates.has(known.toPackage)) {
    candidates.set(known.toPackage, known.targetVersion);
  }

  return candidates;
}

/** Add rename results from candidates, deduplicating by package->target key */
function addResults(
  results: MavenRenameOption[],
  seen: Set<string>,
  finding: Finding,
  candidates: Map<string, string>,
) {
  for (const [toPackage, targetVersion] of candidates) {
    if (toPackage === finding.packageName) continue;
    const key = `${finding.packageName}->${toPackage}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push({
      fromPackage: finding.packageName,
      toPackage,
      targetVersion,
      findingIds: [finding.id, ...finding.aliases.filter(a => a !== finding.id)],
      severity: finding.severity,
    });
  }
}
