import fs from "node:fs";
import path from "node:path";
import { defaultSpinnerFactory, type Spinner, type SpinnerFactory } from "./lib/spinner.ts";
import { parseLockfileAsync, ECOSYSTEM_OSV_NAME } from "./lib/parse-lockfile.ts";
import { matchVulnerabilities } from "./lib/matcher.ts";
import type { Finding, PackageRef, AdvisoryEntry } from "./lib/types.ts";
import { analyzeBuildGradleFile, analyzeMavenPackages } from "./lib/gradle-health.ts";
import { filterPackagesByEcosystem } from "./lib/ecosystem-filter.ts";
import { normalizeCliPath, getOsvDbDir } from "./path.ts";
import { CACHE_TTL_MS } from "./lib/osv-db.ts";
import { downloadOsvEcosystemDump, checkRemoteEtag } from "./lib/osv-export.ts";
import { loadRepoAdvisories } from "./lib/github-repo-advisories.ts";
import { packagesNeedOrphanBridge } from "./lib/osv-package-bridge.ts";
import { loadOrphanBridgedAdvisories } from "./lib/osv-orphan-cves.ts";
import { loadLocalAdvisories } from "./lib/local-advisories.ts";
import { readCacheFile, writeCacheFile, getCacheAgeMs, readCacheEtag, writeCacheEtag } from "./lib/osv-cache.ts";

export { normalizeCliPath, pathHint, repairMangledCliPath, CACHE_DIR, getOsvDbDir } from "./path.ts";
export type { AdvisoryEntry } from "./lib/types.ts";

export { CACHE_TTL_MS } from "./lib/osv-db.ts";
export { readCacheFile, writeCacheFile } from "./lib/osv-cache.ts";

export const DB_DIR = getOsvDbDir();
export const ECOSYSTEM_MAP = ECOSYSTEM_OSV_NAME;

export interface ScanResult {
  packages: PackageRef[];
  findings: Finding[];
  warnings: string[];
  advisories: AdvisoryEntry[];
  resolvedTarget?: string;
  /** Coordinates that failed to resolve in the build (e.g. yanked versions). */
  unresolved?: string[];
}

export interface ScanOptions {
  ecosystemFilter?: string | null;
  /** Suppress banner lines. When true, also disables spinner (legacy). */
  quiet?: boolean;
  /** Suppress "Scanning:" / ecosystem log lines; spinner still runs if `ora` is set. */
  quietBanner?: boolean;
  ora?: SpinnerFactory;
  /** Prepended to spinner text (e.g. fix loop pass 2/10). */
  spinnerPrefix?: string;
  /** Gradle configurations to scan; default runtime+test for both scan and fix. */
  gradleConfigurations?: readonly string[];
  /** Skip live OSV API query; use local cache only. */
  offline?: boolean;
  /** Package coordinates to drop from findings before counting and reporting. */
  excludePackages?: string[];
}

export async function loadAdvisoriesForEcosystem(
  ecosystemKey: string,
  spinner?: Spinner | null,
  offline = false,
): Promise<AdvisoryEntry[]> {
  const osvName = ECOSYSTEM_MAP[ecosystemKey] || ecosystemKey.toUpperCase();
  const logFn = makeLogFn(spinner);

  const cachedData = readCacheFile(osvName);
  if (cachedData === null) return downloadAndCache(osvName, logFn, spinner);
  if (offline) return cachedData;

  // Online: probe the remote dump; re-download only when it changed since we cached it.
  const remoteEtag = await checkRemoteEtag(osvName);
  if (remoteEtag !== null) {
    if (remoteEtag === readCacheEtag(osvName)) {
      logFn(`  Using cached ${osvName} DB (remote unchanged)`);
      return cachedData;
    }
    logFn(`  Remote ${osvName} dump changed, refreshing...`);
    return downloadAndCache(osvName, logFn, spinner);
  }

  // Probe failed (unreachable): fall back to TTL semantics.
  if (isCacheFresh(osvName, logFn)) return cachedData;
  return downloadAndCache(osvName, logFn, spinner);
}

/** Create a no-op or actual logger based on spinner presence */
function makeLogFn(spinner: Spinner | null | undefined): (msg: string) => void {
  return spinner ? () => {} : (msg: string) => console.log(msg);
}

/** Check if cache is fresh enough to use directly */
function isCacheFresh(osvName: string, log: (msg: string) => void): boolean {
  const age = getCacheAgeMs(osvName);
  if (age === null) return false;
  if (age < CACHE_TTL_MS) {
    log(`  Using cached ${osvName} DB (${Math.round(age / 1000 / 60)} min old)`);
    return true;
  }
  log(`  ${osvName} DB cache expired (${Math.round(age / 1000 / 60 / 60)}h old), refreshing...`);
  return false;
}

/** Download, cache, and return advisories with fallback on error */
async function downloadAndCache(
  osvName: string,
  log: (msg: string) => void,
  spinner: Spinner | null | undefined,
): Promise<AdvisoryEntry[]> {
  try {
    if (spinner) spinner.text = `Downloading ${osvName} from OSV...`;
    const result = await downloadOsvEcosystemDump(osvName);
    writeCacheFile(osvName, result.entries);
    if (result.etag !== null) writeCacheEtag(osvName, result.etag);
    log(`  Downloaded & cached: ${result.entries.length} ${osvName} entries`);
    return result.entries;
  } catch (err) {
    if (spinner) spinner.stop();
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  Failed to fetch ${osvName} advisory DB: ${msg}`);
    const fallback = readCacheFile(osvName);
    if (fallback !== null) {
      log(`  Falling back to cached ${osvName} data...`);
      return fallback;
    }
    throw err;
  }
}

export async function prefetchMissingCaches(
  detectedEcosystems: string[],
  oraFactory: SpinnerFactory,
  sharedSpinner?: Spinner,
): Promise<void> {
  const missing = findMissingEcosystems(detectedEcosystems);
  if (missing.length === 0) return;

  reportPrefetchStart(missing, sharedSpinner);

  for (const eco of missing) {
    await prefetchSingleEco(eco, oraFactory, sharedSpinner);
  }

  if (!sharedSpinner) console.log();
}

/** Find ecosystems whose cache files are missing */
function findMissingEcosystems(detectedEcosystems: string[]): string[] {
  return detectedEcosystems.filter(eco => {
    const osvName = ECOSYSTEM_MAP[eco] || eco.toUpperCase();
    return readCacheFile(osvName) === null;
  });
}

/** Log the start of prefetch operation */
function reportPrefetchStart(missing: string[], sharedSpinner: Spinner | undefined): void {
  if (sharedSpinner) return;
  console.log(`\nPrefetching ${missing.length} missing cache(s): ${missing.map(e => ECOSYSTEM_MAP[e] || e.toUpperCase()).join(", ")}...`);
}

/** Prefetch a single ecosystem's advisory database */
async function prefetchSingleEco(
  eco: string,
  oraFactory: SpinnerFactory,
  sharedSpinner: Spinner | undefined,
): Promise<void> {
  const osvName = ECOSYSTEM_MAP[eco] || eco.toUpperCase();
  const label = `Fetching ${osvName} advisory database...`;

  const spinner = sharedSpinner ?? oraFactory(label).start();
    updateSpinnerText(sharedSpinner, label);

  try {
    const advs = await loadAdvisoriesForEcosystem(eco, spinner);
    updateSpinnerResult(sharedSpinner, spinner, `${osvName}: ${advs.length} entries cached`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    updateSpinnerError(sharedSpinner, spinner, `${osvName}: ${msg}`);
  }
}

/** Update shared spinner text (standalone spinners already carry the label) */
function updateSpinnerText(shared: Spinner | undefined, text: string): void {
  if (shared) {
    shared.text = text;
  }
}

/** Show success result on spinner */
function updateSpinnerResult(shared: Spinner | undefined, own: Spinner, text: string): void {
  if (shared) {
    shared.text = text;
  } else {
    own.succeed(text);
  }
}

/** Show warning/error on spinner */
function updateSpinnerError(shared: Spinner | undefined, own: Spinner, text: string): void {
  if (shared) {
    shared.text = text;
  } else {
    own.warn(text);
  }
}

/** Load advisories for one ecosystem (from cache or by download). */
async function loadOneEcosystem(
  eco: string,
  oraFactory?: SpinnerFactory,
  sharedSpinner?: Spinner,
  offline = false,
): Promise<AdvisoryEntry[]> {
  const osvName = ECOSYSTEM_MAP[eco] || eco.toUpperCase();
  const spinner = sharedSpinner ?? oraFactory?.(`Loading ${osvName} advisory database...`).start();
  if (sharedSpinner) sharedSpinner.text = `Loading ${osvName} advisory database...`;
  try {
    const advs = await loadAdvisoriesForEcosystem(eco, spinner, offline);
    if (!sharedSpinner) {
      spinner?.succeed(`${osvName}: ${advs.length} entries`);
    }
    return advs;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (sharedSpinner) {
      throw err;
    }
    spinner?.fail(`${osvName}: ${msg}`);
    throw err;
  }
}

async function loadAdvisoriesForEcosystems(
  ecosystems: string[],
  oraFactory?: SpinnerFactory,
  sharedSpinner?: Spinner,
  offline = false,
): Promise<AdvisoryEntry[]> {
  const allAdvData: AdvisoryEntry[] = [];
  for (const eco of ecosystems) {
    allAdvData.push(...(await loadOneEcosystem(eco, oraFactory, sharedSpinner, offline)));
  }
  return allAdvData;
}

export async function runAutoBumperScan(targetPath: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const { ecosystemFilter = null, quiet = false, quietBanner = quiet, spinnerPrefix } = opts;
  const oraFactory = resolveOraFactory(quiet, opts.ora);
  const resolvedTarget = normalizeCliPath(targetPath);

  if (!quietBanner) console.log(`Scanning: ${resolvedTarget}`);

  const spinner = oraFactory?.("Parsing dependencies...").start();
  const setText = makeSetText(spinner, spinnerPrefix);

  // Phase 1: Parse & filter packages
  const { packages, warnings, unresolved } = await parseAndFilter(resolvedTarget, setText, ecosystemFilter, opts);
  if (packages.length === 0) {
    spinner?.stop();
    return { packages: [], findings: [], warnings, advisories: [], ...(unresolved ? { unresolved } : {}) };
  }

  // Phase 2: Load advisories
  let { allAdvData } = await loadAllAdvisories(
    packages, resolvedTarget, setText, oraFactory, spinner, quietBanner, opts.offline,
  );

  // Bridge package-less OSV records (e.g. log4j CVEs) onto Maven coordinates.
  if (packagesNeedOrphanBridge(packages)) {
    allAdvData = mergeAdvisories(allAdvData, await loadOrphanBridgedAdvisories(packages, { offline: opts.offline }));
  }

  // Phase 3: Load repo-published advisories (vendor GHSAs missing from bulk OSV dumps)
  let repoAdvisories: AdvisoryEntry[] = [];
  if (!opts.offline) {
    try {
      setText("Loading repo-published advisories...");
      repoAdvisories = await loadRepoAdvisories({ setText });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      warnings.push(`GitHub repo advisories unavailable: ${msg}`);
    }
  }
  // Phase 3b: Merge locally-vendored advisories (offline; disclosures not yet in OSV dumps)
  const localAdvisories = loadLocalAdvisories();
  if (localAdvisories.length > 0) {
    setText(`Loaded ${localAdvisories.length} locally-vendored advisories`);
  }
  const combinedData = mergeAdvisories(allAdvData, [...repoAdvisories, ...localAdvisories]);

  // Phase 4: Match & report — excluded coordinates are dropped before counting/reporting
  const allFindings = matchVulnerabilities(packages, combinedData);
  const findings = opts.excludePackages?.length
    ? allFindings.filter(f => !new Set(opts.excludePackages).has(f.packageName))
    : allFindings;
  const healthWarnings = collectHealthWarnings(packages, resolvedTarget);
  const uniqueWarnings = [...new Set([...warnings, ...healthWarnings])];

  // Gradle runtime-only scans say so. A Maven pom scan must not wear that label.
  const gradleScopeNote = gradleScanScopeNote(packages, opts.gradleConfigurations);
  reportStatus(spinner, findings, packages, allAdvData.length, gradleScopeNote);

  return { packages, findings, warnings: uniqueWarnings, advisories: combinedData, resolvedTarget, ...(unresolved ? { unresolved } : {}) };
}

/** Resolve the spinner factory from options */
function resolveOraFactory(quiet: boolean, custom?: SpinnerFactory): SpinnerFactory | undefined {
  if (quiet) return undefined;
  return custom ?? defaultSpinnerFactory;
}

/** Create a text-updater that respects spinner prefix */
function makeSetText(spinner: Spinner | undefined, prefix?: string) {
  return (msg: string) => {
    if (spinner) spinner.text = prefix ? `${prefix} · ${msg}` : msg;
  };
}

/** Parse lockfiles and optionally filter by ecosystem */
async function parseAndFilter(
  resolvedTarget: string,
  setText: (msg: string) => void,
  ecosystemFilter: string | null,
  opts: { gradleConfigurations?: readonly string[] },
): Promise<{ packages: PackageRef[]; warnings: string[]; unresolved?: string[] }> {
  const parseResult = await parseLockfileAsync(
    resolvedTarget,
    setText,
    { gradleConfigurations: opts.gradleConfigurations },
  );
  let packages = parseResult.packages;
  const warnings = [...parseResult.warnings];
  const unresolved = parseResult.unresolved;

  if (ecosystemFilter) {
    packages = filterPackagesByEcosystem(packages, ecosystemFilter);
    if (packages.length === 0) {
      warnings.push(
        `No packages matched --ecosystem=${ecosystemFilter}. Gradle projects resolve as maven coords — use --ecosystem=gradle (build.gradle) or --ecosystem=maven.`,
      );
    }
  }

  return { packages, warnings, ...(unresolved ? { unresolved } : {}) };
}

/** Load cached + live advisories across all ecosystems */
async function loadAllAdvisories(
  packages: PackageRef[],
  resolvedTarget: string,
  setText: (msg: string) => void,
  oraFactory: SpinnerFactory | undefined,
  spinner: Spinner | undefined,
  quietBanner: boolean,
  offline = false,
): Promise<{ allAdvData: AdvisoryEntry[] }> {
  const detectedEcosystems = [...new Set(packages.map(p => p.ecosystem))];
  const hasPom = fs.existsSync(path.join(resolvedTarget, "pom.xml"));
  const hasGradle =
    fs.existsSync(path.join(resolvedTarget, "build.gradle")) ||
    fs.existsSync(path.join(resolvedTarget, "build.gradle.kts"));
  let javaLabel: string | null;
  if (hasPom) {
    javaLabel = "MAVEN";
  } else if (hasGradle) {
    javaLabel = "GRADLE";
  } else {
    javaLabel = null;
  }
  const otherEcos = detectedEcosystems.filter(e => e !== "maven").map(e => e.toUpperCase());
  const ecoLabel = javaLabel
    ? [...otherEcos, javaLabel].join(", ")
    : detectedEcosystems.map(e => e.toUpperCase()).join(", ");

  if (!quietBanner) {
    if (spinner) {
      setText(`${ecoLabel} · ${packages.length} packages — loading advisories...`);
    } else {
      console.log(`Ecosystems: ${ecoLabel}`);
      console.log(`Total packages: ${packages.length}`);
    }
  }

  if (oraFactory) await prefetchMissingCaches(detectedEcosystems, oraFactory, spinner);

  setText("Loading vulnerability database...");
  const allAdvData = await loadAdvisoriesForEcosystems(detectedEcosystems, oraFactory, spinner, offline);

  if (spinner) {
    setText(`Matching ${allAdvData.length} advisory entries...`);
  } else if (!quietBanner) {
    console.log(`Matching against ${allAdvData.length} advisory entries...`);
  }

  return { allAdvData };
}

/** Score how complete an advisory record is (higher = prefer when merging same ID). */
export function advisoryRichness(entry: AdvisoryEntry): number {
  let score = (entry.aliases?.length || 0) + (entry.links?.length || 0);
  if ((entry.summary?.length || 0) > 20) score += 1;
  for (const aff of entry.affected || []) {
    score += (aff.versions?.length || 0) * 2;
    score += (aff.ranges?.length || 0) * 3;
    for (const r of aff.ranges || []) {
      const range = r as {
        events?: unknown[];
        database_specific?: { extracted_events?: unknown[] };
      };
      score += range.events?.length || 0;
      score += (range.database_specific?.extracted_events?.length || 0) * 2;
    }
  }
  return score;
}

/**
 * Merge local cache with live/API advisories by ID.
 * Same ID: keep the richer record so stale cache cannot shadow fresher fixedVersions/ranges.
 */
export function mergeAdvisories(local: AdvisoryEntry[], extra: AdvisoryEntry[]): AdvisoryEntry[] {
  const byId = new Map<string, AdvisoryEntry>();
  for (const e of local) byId.set(e.id, e);
  for (const e of extra) {
    const existing = byId.get(e.id);
    if (!existing || advisoryRichness(e) > advisoryRichness(existing)) {
      byId.set(e.id, e);
    }
  }
  return [...byId.values()];
}

/** Collect health-check warnings for Maven/Gradle packages */
function collectHealthWarnings(packages: PackageRef[], resolvedTarget: string): string[] {
  const warnings = analyzeMavenPackages(packages);
  const hasGradle =
    fs.existsSync(path.join(resolvedTarget, "build.gradle")) ||
    fs.existsSync(path.join(resolvedTarget, "build.gradle.kts"));
  if (hasGradle) {
    const gradleFile = fs.existsSync(path.join(resolvedTarget, "build.gradle"))
      ? path.join(resolvedTarget, "build.gradle")
      : path.join(resolvedTarget, "build.gradle.kts");
    warnings.push(...analyzeBuildGradleFile(gradleFile));
  }
  return warnings;
}

/** Scope suffix for a Gradle runtime-only scan. Empty for pom.xml / non-Java results. */
export function gradleScanScopeNote(
  packages: PackageRef[],
  gradleConfigurations?: readonly string[],
): string {
  if (!gradleConfigurations?.length) return "";
  const sawGradle = packages.some(pkg => {
    const norm = pkg.manifestPath.replaceAll("\\", "/");
    return norm.endsWith("build.gradle") || norm.endsWith("build.gradle.kts");
  });
  if (!sawGradle) return "";
  return ` (Gradle ${gradleConfigurations.join(", ")})`;
}

/** Print final scan status via spinner or console */
function reportStatus(
  spinner: Spinner | undefined,
  findings: Finding[],
  packages: PackageRef[],
  advCount: number,
  scopeNote = "",
) {
  if (spinner) {
    if (findings.length === 0) {
      spinner.succeed(`No vulnerabilities found — ${packages.length} packages, ${advCount} advisories${scopeNote}`);
    } else {
      spinner.warn(`${findings.length} vulnerabilities in ${packages.length} packages${scopeNote}`);
    }
  }
}
