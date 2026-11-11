#!/usr/bin/env bun
/**
 * Auto-Bumper Fix — Polyglot auto-remediation for Java, npm, Rust, Python.
 *
 * Usage:
 *   fix [path] [--dry-run] [--apply] [--allow-major] [--allow-renames] [--allow-downgrades] [--allow-source-migrations] [--apply-excludes] [--force-exclude=group:artifact] [--latest] [--offline] [options]
 *   bun cli/fix.ts [path] [options]   (local dev)
 */
import fs from "node:fs";
import childProcess from "node:child_process";
import path from "node:path";
import readline from "node:readline";
import { defaultSpinnerFactory } from "../src/lib/spinner.ts";
import { runAutoBumperScan, normalizeCliPath, pathHint } from "../src/scan.ts";
import { GRADLE_ALL_CONFIGURATIONS, detectGradlew, detectMaven, listNestedManifests, parseBuildGradleDirect, parsePomXmlDirect, windowsBatchArgs } from "../src/lib/parse-lockfile.ts";
import { buildFixPlan, familyOf, majorOf, packageAdvisoryEntries, pickSafeEscapeVersion, planFamilyMigrations, withDowngradeVersion, withNextFixVersion } from "../src/lib/fixer.ts";
import type { FixCandidate, FixPlan } from "../src/lib/fixer.ts";
import { bumpApplyMethod, normalizeBumpApplyResult, type BumpApplyResult } from "../src/lib/apply-method.ts";
import { selectUnresolvableRollbacks } from "../src/lib/unresolvable.ts";
import { findLatestAvailableVersion, findNextAvailableVersion, isPreReleaseOrSnapshot, listAvailableVersions, versionPublishedInRepos } from "../src/lib/repo-metadata.ts";
import { computeProtectedPins, fetchBomManagedVersions } from "../src/lib/bom-managed.ts";
import { compareMavenVersion, isVersionAffected, isVersionAffectedByAdvisories, matchVulnerabilities } from "../src/lib/matcher.ts";
import {
  applyBumps as applyGradleBumps,
  applyRenames as applyGradleRenames,
  backupBuildGradle,
  detectGradlePlatform,
  discardBackup as discardGradleBackup,
  findShadowedManagedPins,
  findStaleManagedPins,
  parseUserForces,
  removeManagedPin as removeGradleManagedPin,
  restoreBuildGradle,
  restoreDeclaredVersion as restoreGradleDeclaredVersion,
} from "../src/lib/gradle-editor.ts";
import type { GradlePlatform, RenameRequest, ShadowedManagedPin, StaleManagedPin } from "../src/lib/gradle-editor.ts";
import {
  applyBumps as applyMavenBumps,
  applyRenames as applyMavenRenames,
  backupPomXml,
  discardBackup as discardMavenBackup,
  removeManagedPin as removeMavenManagedPin,
  restorePomXml,
} from "../src/lib/pom-editor.ts";
import {
  applyBumps as applyNpmBumps,
  applyRenames as applyNpmRenames,
  backupPackageJson,
  discardBackup as discardNpmBackup,
  restorePackageJson,
  findPackageJson,
  type BumpRequest,
  type RenameRequest as NpmRenameRequest,
} from "../src/lib/npm-editor.ts";
import {
  applyBumps as applyCargoBumps,
  applyRenames as applyCargoRenames,
  backupCargoToml,
  discardBackup as discardCargoBackup,
  restoreCargoToml,
} from "../src/lib/cargo-editor.ts";
import {
  applyToRequirementsTxt,
  applyToPyprojectToml,
  applyRenamesToRequirementsTxt,
  applyRenamesToPyprojectToml,
  backupRequirementsTxt,
  discardRequirementsBackup,
  restoreRequirementsTxt,
  backupPyprojectToml,
  discardPyprojectBackup,
  restorePyprojectToml,
} from "../src/lib/python-editor.ts";
import {
  analyzeBuildGradleFile,
  analyzeFixPlan,
} from "../src/lib/gradle-health.ts";
import { applyPolicyForRenames, consumerVariantsForFamily, expandRenameBundle, KNOWN_RENAMES, sourceMigrationsForAppliedRenames, topLevelAncestors } from "../src/lib/maven-renames.ts";
import { scanEcosystemFilterForKind } from "../src/lib/ecosystem-filter.ts";
import type { RenameApplyPolicy, SourceMigrationConfig } from "../src/lib/maven-renames.ts";
import {
  applySourceMigrations,
  describeSourceMigrations,
  discardSourceMigrationBackups,
  restoreSourceMigrationBackups,
} from "../src/lib/source-migrations.ts";
import { discardStaleBackup, runApplyTransaction } from "../src/lib/backup.ts";
import type { AdvisoryEntry, Finding, PackageRef } from "../src/lib/types.ts";
import {
  filterRedundantFixes,
  planSignature,
  renamesForMixedClasspathCompletion,
} from "../src/lib/fix-plan-filter.ts";
import {
  findingSignature,
  fixLoopStopReason,
  fixLoopStopMessage,
} from "../src/lib/fix-loop.ts";
import {
  overlayManifestDirectDeps,
  MANIFEST_OVERLAY_WARNING,
  fixLoopBlockedMessage,
} from "../src/lib/manifest-overlay.ts";
import { lockRefreshCommands, refreshProjectLocks } from "../src/lib/lockfile-refresh.ts";
import { renameNeedsSourceMigration } from "../src/lib/rename-source-gate.ts";

const args = process.argv.slice(2);
const targetPath = args.find(a => !a.startsWith("--")) || ".";
if (args.includes("--yolo")) {
  console.error("Error: --yolo was removed. Use --apply. Add --strict to exit 1 if vulnerabilities remain.");
  process.exit(2);
}
const dryRun = args.includes("--dry-run");
const applyFlag = args.includes("--apply");
const allowMajor = args.includes("--allow-major");
const allowDowngrades = args.includes("--allow-downgrades");
const allowRenames = args.includes("--allow-renames");
const applyExcludes = args.includes("--apply-excludes");
const deprecatedJavaImports = args.includes("--allow-java-imports");
const allowSourceMigrations = args.includes("--allow-source-migrations") || deprecatedJavaImports;
if (deprecatedJavaImports) {
  console.error("Warning: --allow-java-imports is deprecated; use --allow-source-migrations");
}
const offlineFlag = args.includes("--offline");

const latestFlag = args.includes("--latest");
if (latestFlag && offlineFlag) {
  console.error("Error: --latest requires network access; drop --offline.");
  process.exit(2);
}
const strictExit = args.includes("--strict");
const formatFlag = args.find(a => a.startsWith("--format"));
const outputFormat = formatFlag ? formatFlag.split("=")[1] : "markdown";
const maxIterFlag = args.find(a => a.startsWith("--max-iterations"));
const maxIterations = maxIterFlag
  ? Number.parseInt(maxIterFlag.split("=")[1]!, 10)
  : 10;
const excludeArgs = args.filter(a => a.startsWith("--exclude=")).map(a => a.split("=")[1]!);
const forceExcludeArgs = args.filter(a => a.startsWith("--force-exclude=")).map(a => a.split("=")[1]!);
const forceExcludeCoords = new Set(forceExcludeArgs.map(s => s.toLowerCase()));
const ecosystemFlag = args.find(a => a.startsWith("--ecosystem="));
const ecosystemFilter = ecosystemFlag ? ecosystemFlag.split("=")[1]?.toLowerCase() : null;

const isTTY = process.stdin.isTTY && process.stdout.isTTY;

// Supported auto-fix ecosystems
type FixEcosystem = "maven" | "gradle" | "npm" | "crates.io" | "pypi";
interface ProjectInfo {
  kind: FixEcosystem;
  manifestPath: string;
  label: string;
}

interface AppliedBump {
  packageName: string;
  from: string;
  to: string;
  method: string;
  findingIds: string[];
  isRename?: boolean;
  manifestPath?: string;
  /** True for preemptive --latest bumps (no advisory finding). */
  latest?: boolean;
  /** True when this bump moved the project to an OLDER release (downgrade-only fix). */
  isDowngrade?: boolean;
}

/** One coherent whole-family migration executed in this run (all members pinned to one version). */
interface FamilyMigrationReport {
  family: string;
  targetVersion: string;
  memberCount: number;
  /** Members whose coordinate was renamed as part of the migration (old -> new). */
  renamedMembers?: Record<string, string>;
  /** Consumer artifacts swapped to an ecosystem-specific variant as part of the migration (base -> variant). */
  consumerVariants?: Record<string, string>;
}

/** Detect ALL fixable projects in directory */
function findProjects(dir: string, filter?: string | null): ProjectInfo[] {
  const resolved = normalizeCliPath(dir);
  const projects: ProjectInfo[] = [];

  // npm
  const pkgJson = findPackageJson(resolved);
  if (pkgJson && (!filter || filter === "npm")) {
    projects.push({ kind: "npm", manifestPath: pkgJson, label: "npm" });
  }

  // Rust
  const cargoToml = path.join(resolved, "Cargo.toml");
  if (fs.existsSync(cargoToml) && (!filter || filter === "crates.io")) {
    projects.push({ kind: "crates.io", manifestPath: cargoToml, label: "Rust" });
  }

  // Python — edit every manifest that can declare the pin. A tooling-only
  // pyproject.toml must not hide requirements.txt, and Poetry needs both.
  const reqTxt = path.join(resolved, "requirements.txt");
  const pyproject = path.join(resolved, "pyproject.toml");
  if (!filter || filter === "pypi") {
    const hasReq = fs.existsSync(reqTxt);
    const hasPy = fs.existsSync(pyproject);
    if (hasReq) {
      projects.push({
        kind: "pypi",
        manifestPath: reqTxt,
        label: hasPy ? "Python (requirements.txt)" : "Python",
      });
    }
    if (hasPy) {
      projects.push({
        kind: "pypi",
        manifestPath: pyproject,
        label: hasReq ? "Python (pyproject.toml)" : "Python",
      });
    }
  }

  const pom = path.join(resolved, "pom.xml");
  const gradle = path.join(resolved, "build.gradle");
  const gradleKts = path.join(resolved, "build.gradle.kts");
  if (fs.existsSync(pom) && (!filter || filter === "maven")) {
    projects.push({ kind: "maven", manifestPath: pom, label: "Maven" });
  }
  if (fs.existsSync(gradle) && (!filter || filter === "gradle")) {
    projects.push({ kind: "gradle", manifestPath: gradle, label: "Gradle" });
  } else if (fs.existsSync(gradleKts) && (!filter || filter === "gradle")) {
    projects.push({ kind: "gradle", manifestPath: gradleKts, label: "Gradle" });
  }

  const nestedLabel: Record<string, string> = {
    maven: "Maven",
    gradle: "Gradle",
    npm: "npm",
    "crates.io": "Rust",
    pypi: "Python",
  };
  for (const manifest of listNestedManifests(resolved)) {
    const ecoFilter = manifest.kind === "crates.io" ? "crates.io" : manifest.kind === "pypi" ? "pypi" : manifest.kind;
    if (filter && filter !== ecoFilter) continue;
    const rel = path.relative(resolved, manifest.filePath).replaceAll("\\", "/");
    projects.push({
      kind: manifest.kind,
      manifestPath: manifest.filePath,
      label: `${nestedLabel[manifest.kind] ?? manifest.kind} (${rel})`,
    });
  }

  return projects;
}

function ask(question: string): Promise<boolean> {
  if (!isTTY) return Promise.resolve(false);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
  });
}

interface PlanReportOptions {
  applied: AppliedBump[];
  unfixableRemaining: FixCandidate[];
  excludeFailed?: Set<string>;
  labels: string[];
  skippedMajors: FixCandidate[];
  remainingFindings?: Array<{ packageName: string; installedVersion: string; id: string; aliases: string[] }>;
  skippedRenames?: FixCandidate[];
  healthWarnings?: string[];
  familyMigrations?: FamilyMigrationReport[];
  sourceMigrations?: SourceMigrationConfig | null;
  skippedSourceMigrations?: boolean;
  skippedUnresolvable?: AppliedBump[];
}

function pushHealthWarnings(lines: string[], warnings: string[]): void {
  if (warnings.length === 0) return;
  lines.push(`## Health warnings (${warnings.length})`, "");
  for (const w of warnings) lines.push(`- ${w}`);
  lines.push("");
}

function pushApplied(lines: string[], applied: AppliedBump[]): void {
  if (applied.length === 0) return;
  lines.push(`## Applied (${applied.length})`, "");
  for (const a of applied) {
    const ref = a.latest ? "(latest)" : a.findingIds.length > 0 ? `[${a.findingIds.join(", ")}]` : "(co-versioned pin)";
    lines.push(`- ${a.packageName}: ${a.from} -> ${a.to} (${a.method}) ${ref}`);
  }
  lines.push("");
}

function pushFamilyMigrations(lines: string[], migrations: FamilyMigrationReport[]): void {
  if (migrations.length === 0) return;
  lines.push(`## Family migrations (${migrations.length})`, "");
  for (const m of migrations) {
    const renames = Object.entries(m.renamedMembers ?? {}).map(([from, to]) => `${from.split(":")[1]} -> ${to.split(":")[1]}`);
    const variants = Object.entries(m.consumerVariants ?? {}).map(([from, to]) => `${from.split(":")[1]} -> ${to.split(":")[1]}`);
    lines.push(`- family '${m.family}': ${m.memberCount} artifacts pinned to ${m.targetVersion}${renames.length + variants.length > 0 ? ` (${[...renames, ...variants].join(", ")})` : ""} — the co-versioned family moves together; verify compatibility with dependencies built against the old line (e.g. test-scope stubs)`);
  }
  lines.push("");
}

function pushPlannedBumps(lines: string[], fixable: FixCandidate[]): void {
  if (fixable.length === 0) return;
  lines.push(`## Planned bumps (${fixable.length})`, "", "| Package | Current | Target | Major | Advisories |", "|---------|---------|--------|-------|------------|");
  for (const c of fixable) {
    lines.push(`| ${c.packageName} | ${c.installedVersion} | ${c.targetVersion}${c.isDowngrade ? " ↓" : ""} | ${c.isMajor ? "yes" : "no"} | ${c.findingIds.length > 0 ? c.findingIds.slice(0, 2).join(", ") : "—"} |`);
  }
  if (fixable.some(c => c.isDowngrade)) lines.push("- Downgrades (↓) move to an OLDER GA release — pre-releases, milestones, RCs and Java builds are never downgrade targets. Applied only with --allow-downgrades; a downgrade crossing a major boundary is additionally gated by --allow-major. Each is compile-checked and rolled back automatically if the build fails.");
  lines.push("");
}

function pushPlannedRenames(lines: string[], renames: FixCandidate[]): void {
  if (renames.length === 0) return;
  lines.push(`## Planned renames (${renames.length})`, "", "| From | To | Version | Advisories |", "|------|----|---------|------------|");
  for (const c of renames) {
    lines.push(`| ${c.packageName} | ${c.renameTo} | ${c.targetVersion} | ${c.findingIds.slice(0, 2).join(", ")} |`);
  }
  lines.push("");
}

function pushSourceMigrations(lines: string[], sourceMigrations: SourceMigrationConfig | null, skippedSourceMigrations: boolean): void {
  if (!sourceMigrations) return;
  lines.push("## Planned source migrations", "");
  for (const line of describeSourceMigrations(sourceMigrations)) {
    lines.push(`- ${line}`);
  }
  lines.push("- Import prefix rewrites only — API breaking changes may still need manual fixes.");
  if (skippedSourceMigrations) {
    lines.push("- Source migrations skipped — use --allow-source-migrations (with --allow-renames) or approve at prompt.");
  }
  lines.push("");
}

function pushSkippedRenames(lines: string[], skippedRenames: FixCandidate[]): void {
  if (skippedRenames.length === 0) return;
  lines.push(`## Skipped renames (${skippedRenames.length})`, "");
  for (const s of skippedRenames) {
    lines.push(`- ${s.packageName} -> ${s.renameTo} @ ${s.targetVersion} (declined or use --allow-renames)`);
  }
  lines.push("");
}

function pushSkippedMajors(lines: string[], skippedMajors: FixCandidate[]): void {
  if (skippedMajors.length === 0) return;
  lines.push(`## Skipped major version changes (${skippedMajors.length})`, "");
  for (const s of skippedMajors) {
    lines.push(`- ${s.packageName}: ${s.installedVersion} -> ${s.targetVersion} (declined or use --allow-major)`);
  }
  lines.push("");
}

function pushSkippedUnresolvable(lines: string[], skippedUnresolvable: AppliedBump[]): void {
  if (skippedUnresolvable.length === 0) return;
  lines.push(`## Skipped — target not resolvable (${skippedUnresolvable.length})`, "");
  for (const s of skippedUnresolvable) {
    lines.push(`- ${s.packageName}: rolled back ${s.from} -> ${s.to} — version ${s.to} not found in project repositories`);
  }
  lines.push("");
}

function pushUnfixable(lines: string[], unfixable: FixCandidate[], unfixableRemaining: FixCandidate[], excludeFailed?: Set<string>): void {
  if (unfixable.length === 0 && unfixableRemaining.length === 0) return;
  const seen = new Set<string>();
  const all: FixCandidate[] = [];
  for (const u of [...unfixable, ...unfixableRemaining]) {
    const key = `${u.packageName}@${u.installedVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);
    all.push(u);
  }
  lines.push(`## Unfixable (${all.length})`, "");
  for (const u of all) {
    if (excludeFailed?.has(u.packageName)) {
      lines.push(`- ${u.packageName}@${u.installedVersion} — no fixed version in OSV, and it cannot be excluded (likely a direct dependency) — remove it from the manifest manually, or use --exclude=${u.packageName}`);
    } else if (u.familyClamped) {
      lines.push(`- ${u.packageName}@${u.installedVersion} — ${u.familyClamped} (consider --exclude=${u.packageName}, or re-run with --apply-excludes)`);
    } else if (u.downgradeTarget) {
      const crossesMajor = majorOf(u.downgradeTarget!) !== majorOf(u.installedVersion);
      lines.push(`- ${u.packageName}@${u.installedVersion} — no fixed version in OSV; GA downgrade target ${u.downgradeTarget} available (below introduced ${u.introduced ?? "?"}) — pass --allow-downgrades to apply it${crossesMajor ? ` (crosses major boundary — also pass --allow-major)` : ""}${u.preReleaseOnlyFix ? ` (forward fix exists only as pre-release ${u.preReleaseOnlyFix})` : ""}`);
    } else if (u.preReleaseOnlyFix) {
      lines.push(`- ${u.packageName}@${u.installedVersion} — no GA fix available; only pre-release ${u.preReleaseOnlyFix} fixes this — manual decision required (accept the pre-release, or --exclude=${u.packageName})`);
    } else {
      lines.push(`- ${u.packageName}@${u.installedVersion} — no fixed version in OSV (consider --exclude=${u.packageName}, or re-run with --apply-excludes)`);
    }
  }
  lines.push("");
}

function pushRemainingFindings(lines: string[], remainingFindings: Array<{ packageName: string; installedVersion: string; id: string; aliases: string[] }>): void {
  if (remainingFindings.length === 0) return;
  lines.push(`## Remaining vulnerabilities (${remainingFindings.length})`, "", "| Package | Installed | Advisory |", "|---------|-----------|----------|");
  for (const f of remainingFindings) {
    const alias = f.aliases[0] || f.id;
    lines.push(`| \`${f.packageName}\` | ${f.installedVersion} | ${alias} |`);
  }
  lines.push("");
}

function planMarkdown(plan: FixPlan, opts: PlanReportOptions): string {
  const label = opts.labels.length === 1 ? opts.labels[0] : opts.labels.join(", ");
  const lines = [`# Auto-Bumper ${label} Fix Report`, ""];
  pushHealthWarnings(lines, opts.healthWarnings ?? []);
  pushFamilyMigrations(lines, opts.familyMigrations ?? []);
  pushApplied(lines, opts.applied);
  pushPlannedBumps(lines, [...plan.fixable, ...plan.downgrades]);
  pushPlannedRenames(lines, plan.renames);
  pushSourceMigrations(lines, opts.sourceMigrations ?? null, opts.skippedSourceMigrations ?? false);
  pushSkippedRenames(lines, opts.skippedRenames ?? []);
  pushSkippedMajors(lines, opts.skippedMajors);
  pushSkippedUnresolvable(lines, opts.skippedUnresolvable ?? []);
  pushUnfixable(lines, plan.unfixable, opts.unfixableRemaining, opts.excludeFailed);
  pushRemainingFindings(lines, opts.remainingFindings ?? []);
  return lines.join("\n");
}

async function filterByMajorGate(candidates: FixCandidate[], verb: "bump" | "downgrade" = "bump") {
  const approved: FixCandidate[] = [];
  const skipped: FixCandidate[] = [];

  for (const c of candidates) {
    if (!c.isMajor) {
      approved.push(c);
      continue;
    }
    if (allowMajor) {
      approved.push(c);
      continue;
    }
    if (dryRun) {
      skipped.push(c);
      continue;
    }
    if (isTTY) {
      const ok = await ask(
        `Major ${verb} ${c.packageName}: ${c.installedVersion} -> ${c.targetVersion}? [y/N] `,
      );
      if (ok) approved.push(c);
      else skipped.push(c);
    } else {
      skipped.push(c);
    }
  }

  return { approved, skipped };
}

async function filterByRenameGate(candidates: FixCandidate[]) {
  const approved: FixCandidate[] = [];
  const skipped: FixCandidate[] = [];

  for (const c of candidates) {
    if (allowRenames) {
      approved.push(c);
      continue;
    }
    if (dryRun) {
      skipped.push(c);
      continue;
    }
    if (isTTY) {
      const ok = await ask(
        `Rename ${c.packageName} -> ${c.renameTo} @ ${c.targetVersion}? [y/N] `,
      );
      if (ok) approved.push(c);
      else skipped.push(c);
    } else {
      skipped.push(c);
    }
  }

  return { approved, skipped };
}

/** Gate for unfixable packages: exclude them from the dependency graph when approved. Exclusions are only expressible in Maven/Gradle manifests. */
export async function filterByExcludeGate(
  unfixable: FixCandidate[],
  projects: ProjectInfo[],
  preApproved: Set<string>,
  failed: Set<string>,
  packages: PackageRef[],
  forceExclude: Set<string>,
): Promise<{ approved: FixCandidate[]; warnings: string[] }> {
  const approved: FixCandidate[] = [];
  const warnings: string[] = [];
  if (!projects.some(isMavenLike)) return { approved, warnings };
  // coordinate (lowercase) -> PackageRef, so each candidate's own dependents can be read from its requiredBy edge list.
  const byCoord = new Map<string, PackageRef>();
  for (const p of packages) byCoord.set(p.name.toLowerCase(), p);
  const seen = new Set<string>();
  for (const c of unfixable) {
    if (c.ecosystem && c.ecosystem !== "maven") continue;
    if (!c.packageName.includes(":")) continue;
    if (seen.has(c.packageName)) continue;
    seen.add(c.packageName);
    if (failed.has(c.packageName)) continue;
    // requiredBy lists the coordinates that require this one on the resolved classpath. Excluding it from all
    // configurations would remove classes those dependents still load. Refuse unless explicitly forced.
    const dependents = [...(byCoord.get(c.packageName.toLowerCase())?.requiredBy ?? [])];
    if (dependents.length > 0 && !forceExclude.has(c.packageName.toLowerCase())) {
      warnings.push(`Refused to exclude ${c.packageName} (no fix version): required by ${dependents.join(", ")} on the resolved classpath — removing it from all configurations breaks class loading. Exclude it manually in the manifest if you accept the risk, or pass --force-exclude=${c.packageName}.`);
      continue;
    }
    if (dryRun) continue;
    if (applyExcludes || preApproved.has(c.packageName)) {
      approved.push(c);
      continue;
    }
    if (isTTY) {
      const ok = await ask(
        `Exclude ${c.packageName}@${c.installedVersion} from the dependency graph (no fix version exists)? It is removed at runtime — verify no code path needs it. [y/N] `,
      );
      if (ok) approved.push(c);
    }
  }

  return { approved, warnings };
}

async function filterBySourceGate(
  renames: FixCandidate[],
  hasApprovedRenames: boolean,
): Promise<{ approved: boolean }> {
  const config = sourceMigrationsForAppliedRenames(renamesForSourceMigrations(renames));
  if (!config || !hasApprovedRenames) return { approved: false };

  if (allowSourceMigrations) return { approved: true };
  if (dryRun) return { approved: false };
  if (isTTY) {
    const ok = await ask("Apply source migrations for renamed coordinates? [y/N] ");
    return { approved: ok };
  }
  return { approved: false };
}

function dedupeApplied(applied: AppliedBump[]): AppliedBump[] {
  const seen = new Set<string>();
  const out: AppliedBump[] = [];
  for (const a of applied) {
    const key = `${a.packageName}|${a.from}|${a.to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}

function recordApplied(
  applied: AppliedBump[],
  seen: Set<string>,
  entry: AppliedBump,
): boolean {
  const key = `${entry.packageName}|${entry.from}|${entry.to}`;
  if (seen.has(key)) return false;
  seen.add(key);
  applied.push(entry);
  return true;
}

/** Key for a candidate's target coordinate@version (renames key on the new coordinate). */
function unresolvableKey(c: { packageName: string; targetVersion?: string | null; renameTo?: string }): string {
  return `${(c.renameTo ?? c.packageName).toLowerCase()}@${(c.targetVersion ?? "").toLowerCase()}`;
}

/** Filter out candidates whose target coordinate@version is known-unresolvable this session; log each drop. */
function dropUnresolvable<T extends { packageName: string; targetVersion?: string | null; renameTo?: string }>(list: T[], sessionUnresolvable: Set<string>): T[] {
  const kept = list.filter(c => !sessionUnresolvable.has(unresolvableKey(c)));
  for (const c of list) {
    if (!kept.includes(c)) console.log(`  ~ skipped: ${c.packageName} — target version not resolvable from project repositories`);
  }
  return kept;
}

/** Re-target an applied bump to the smallest repository version above the failed one; true on success. */
async function reTargetUnresolvable(r: AppliedBump, project: ProjectInfo & { kind: "maven" | "gradle" }, appliedKeys: Set<string>): Promise<boolean> {
  const next = await findNextAvailableVersion(project.manifestPath, project.kind, r.packageName, r.to);
  if (!next) return false;
  const failed = r.to;
  applyManifestBumps(project, [
    { packageName: r.packageName, targetVersion: next, because: [`re-targeted: ${failed} unavailable in project repositories`] },
  ], []);
  appliedKeys.delete(`${r.packageName}|${r.from}|${failed}`);
  r.to = next;
  appliedKeys.add(`${r.packageName}|${r.from}|${next}`);
  console.log(`  ~ re-targeted ${r.packageName}: version ${failed} not available in project repositories, using ${next} instead`);
  return true;
}

/** Restore the declared version for a direct bump that is being rolled back. */
function restoreDirectBump(project: ProjectInfo, r: AppliedBump): void {
  if (project.kind === "gradle") {
    if (!restoreGradleDeclaredVersion(project.manifestPath, r.packageName, r.from, r.to)) {
      console.log(`  ! could not restore declared version for ${r.packageName} — expected ${r.to}, file may have changed since apply`);
    }
  } else {
    const inverse = applyManifestBumps(project, [
      { packageName: r.packageName, targetVersion: r.from, because: ["rollback-unresolvable"] },
    ], []);
    for (const w of inverse.warnings) console.log(`  [${project.label}] ${w}`);
  }
}

/** Roll back (or re-target) one applied bump whose target is unresolvable; returns manifest changes made. */
async function handleUnresolvableRecord(
  r: AppliedBump,
  project: ProjectInfo | undefined,
  allApplied: AppliedBump[],
  appliedKeys: Set<string>,
  allSkippedUnresolvable: AppliedBump[],
  sessionUnresolvable: Set<string>,
): Promise<number> {
  if (project && isMavenLike(project)) {
    const mavenProject = project; // narrowed copy — property checks don't narrow the object itself in TS 5.x
    try {
      // Prefer re-targeting: smallest version in the project repositories above the failed one.
      if (await reTargetUnresolvable(r, mavenProject, appliedKeys)) return 1;

      console.log(`  ! no version above ${r.to} found in project repositories for ${r.packageName} — rolling back`);
      // No alternative version — full rollback.
      const removePin = project.kind === "gradle" ? removeGradleManagedPin : removeMavenManagedPin;
      removePin(project.manifestPath, r.packageName);
      if (r.method === "direct") restoreDirectBump(project, r);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ! rollback of ${r.packageName} failed: ${msg}`);
      return 0;
    }
  }
  const idx = allApplied.indexOf(r);
  if (idx !== -1) allApplied.splice(idx, 1);
  appliedKeys.delete(`${r.packageName}|${r.from}|${r.to}`);
  allSkippedUnresolvable.push(r);
  sessionUnresolvable.add(`${r.packageName.toLowerCase()}@${r.to.toLowerCase()}`);
  console.log(`  ~ rolled back ${r.packageName}: target ${r.to} not resolvable from project repositories (kept ${r.from})`);
  return 1;
}

/**
 * Handle applied bumps whose target version cannot be resolved (e.g. yanked releases).
 * Prefers re-targeting to the smallest version available in the project's repositories
 * above the failed one; falls back to a full rollback (remove pins, restore the original
 * declared version). Returns the number of manifest changes made (re-targets + rollbacks).
 */
async function rollBackUnresolvable(
  records: AppliedBump[],
  projects: ProjectInfo[],
  allApplied: AppliedBump[],
  appliedKeys: Set<string>,
  allSkippedUnresolvable: AppliedBump[],
  sessionUnresolvable: Set<string>,
): Promise<number> {
  let count = 0;
  for (const r of records) {
    const project = projects.find(p => p.manifestPath === r.manifestPath);
    count += await handleUnresolvableRecord(r, project, allApplied, appliedKeys, allSkippedUnresolvable, sessionUnresolvable);
  }
  return count;
}

function backupManifest(project: ProjectInfo): void {
  switch (project.kind) {
    case "maven": backupPomXml(project.manifestPath); break;
    case "gradle": backupBuildGradle(project.manifestPath); break;
    case "npm": backupPackageJson(project.manifestPath); break;
    case "crates.io": backupCargoToml(project.manifestPath); break;
    case "pypi":
      if (project.manifestPath.endsWith("pyproject.toml")) backupPyprojectToml(project.manifestPath);
      else backupRequirementsTxt(project.manifestPath);
      break;
  }
}

function restoreManifestBackup(project: ProjectInfo): boolean {
  switch (project.kind) {
    case "maven": return restorePomXml(project.manifestPath);
    case "gradle": return restoreBuildGradle(project.manifestPath);
    case "npm": return restorePackageJson(project.manifestPath);
    case "crates.io": return restoreCargoToml(project.manifestPath);
    case "pypi":
      return project.manifestPath.endsWith("pyproject.toml")
        ? restorePyprojectToml(project.manifestPath)
        : restoreRequirementsTxt(project.manifestPath);
    default: return false;
  }
}

function restoreSession(projects: ProjectInfo[], sourcePaths: string[]): void {
  for (const p of projects) restoreManifestBackup(p);
  restoreSourceMigrationBackups(sourcePaths);
}

function discardManifestBackup(project: ProjectInfo): void {
  switch (project.kind) {
    case "maven": discardMavenBackup(project.manifestPath); break;
    case "gradle": discardGradleBackup(project.manifestPath); break;
    case "npm": discardNpmBackup(project.manifestPath); break;
    case "crates.io": discardCargoBackup(project.manifestPath); break;
    case "pypi":
      if (project.manifestPath.endsWith("pyproject.toml")) discardPyprojectBackup(project.manifestPath);
      else discardRequirementsBackup(project.manifestPath);
      break;
  }
}

function applyManifestBumps(project: ProjectInfo, bumps: BumpRequest[], excludes: { packageName: string; attachTo?: string[] }[], bomManaged: ReadonlyMap<string, string> | null = null, protectedPins?: ReadonlySet<string>): BumpApplyResult {
  if (project.kind === "maven") return normalizeBumpApplyResult(applyMavenBumps(project.manifestPath, bumps, excludes));
  if (project.kind === "gradle") return normalizeBumpApplyResult(applyGradleBumps(project.manifestPath, bumps, excludes, bomManaged, protectedPins));
  if (project.kind === "npm") return normalizeBumpApplyResult(applyNpmBumps(project.manifestPath, bumps, excludes));
  if (project.kind === "crates.io") return normalizeBumpApplyResult(applyCargoBumps(project.manifestPath, bumps, excludes));
  if (project.manifestPath.endsWith("pyproject.toml")) return normalizeBumpApplyResult(applyToPyprojectToml(project.manifestPath, bumps, excludes));
  return normalizeBumpApplyResult(applyToRequirementsTxt(project.manifestPath, bumps, excludes));
}

function applyManifestRenames(project: ProjectInfo, renames: RenameRequest[]) {
  if (project.kind === "gradle") return applyGradleRenames(project.manifestPath, renames);
  if (project.kind === "maven") return applyMavenRenames(project.manifestPath, renames);
  if (project.kind === "npm") {
    const result = applyNpmRenames(project.manifestPath, renames as NpmRenameRequest[]);
    return {
      direct: result.bumped,
      constrained: [] as string[],
      warnings: result.warnings,
    };
  }
  if (project.kind === "crates.io") {
    const result = applyCargoRenames(project.manifestPath, renames as NpmRenameRequest[]);
    return {
      direct: result.bumped,
      constrained: [] as string[],
      warnings: result.warnings,
    };
  }
  if (project.kind === "pypi") {
    const result = project.manifestPath.endsWith("pyproject.toml")
      ? applyRenamesToPyprojectToml(project.manifestPath, renames as NpmRenameRequest[])
      : applyRenamesToRequirementsTxt(project.manifestPath, renames as NpmRenameRequest[]);
    return {
      direct: result.bumped,
      constrained: [] as string[],
      warnings: result.warnings,
    };
  }
  return { direct: [] as string[], constrained: [] as string[], warnings: [] as string[] };
}

/**
 * Load platform BOM managed-version maps for Gradle projects (best-effort, cached per BOM version).
 * Skipped in offline mode; failures leave the project without a map (no cleanup, no pin filtering).
 */
async function loadBomManagedMaps(projects: ProjectInfo[]): Promise<Map<string, Map<string, string>>> {
  const maps = new Map<string, Map<string, string>>();
  if (offlineFlag) return maps;
  for (const project of projects) {
    if (project.kind !== "gradle") continue;
    let platform: GradlePlatform | null = null;
    try {
      platform = detectGradlePlatform(project.manifestPath);
    } catch {
      // Unreadable build file — no BOM map.
    }
    if (!platform) continue;
    const bomMap = await fetchBomManagedVersions(project.manifestPath, platform.group, platform.artifact, platform.version);
    if (bomMap) maps.set(project.manifestPath, bomMap);
  }
  return maps;
}

/** Per-project protected pins: stale managed pins whose removal would reintroduce a known vulnerability. */
export function computeProtectedPinsByProject(projects: ProjectInfo[], bomMaps: Map<string, Map<string, string>>, advisories: readonly AdvisoryEntry[]): Map<string, Map<string, StaleManagedPin>> {
  const out = new Map<string, Map<string, StaleManagedPin>>();
  for (const p of projects) {
    if (p.kind !== "gradle") continue;
    const map = bomMaps.get(p.manifestPath);
    if (!map) continue;
    try {
      const content = fs.readFileSync(p.manifestPath, "utf-8");
      let pins = computeProtectedPins(content, map, advisories);
      // A pin the project's own force already covers at or above is normally not protected: the
      // user's explicit decision wins, and keeping our escape pin would split the co-versioned
      // family. Exception: when the user-forced version is itself affected — then our pin (last
      // resolutionStrategy.force wins) is what keeps the tree clean, and dropping it would
      // reintroduce the vulnerability.
      const shadowed = findShadowedManagedPins(content);
      if (shadowed.length > 0) {
        pins = new Map(
          [...pins].filter(([pkg]) => {
            const sh = shadowed.find(s => s.packageName === pkg);
            return !sh || isVersionAffectedByAdvisories(pkg, sh.userVersion, "maven", advisories);
          }),
        );
      }
      if (pins.size > 0) out.set(p.manifestPath, pins);
    } catch {
      // Unreadable build file — skip.
    }
  }
  return out;
}

/** Set of protected pin names for one project (undefined when there are none). */
function protectedNames(protectedByProject: ReadonlyMap<string, ReadonlyMap<string, StaleManagedPin>> | undefined, project: ProjectInfo): ReadonlySet<string> | undefined {
  const pins = protectedByProject?.get(project.manifestPath);
  return pins ? new Set(pins.keys()) : undefined;
}

/** True when the managed block has pins to clean up: BOM-stale (not vulnerability escapes) or shadowed by the project's own force. */
function bomPinCleanupNeeded(project: ProjectInfo, bomMaps: Map<string, Map<string, string>>, protectedByProject?: ReadonlyMap<string, ReadonlyMap<string, StaleManagedPin>>): boolean {
  if (project.kind !== "gradle") return false;
  try {
    const content = fs.readFileSync(project.manifestPath, "utf-8");
    const map = bomMaps.get(project.manifestPath);
    const prot = protectedNames(protectedByProject, project);
    if (map && findStaleManagedPins(content, map, prot).length > 0) return true;
    return findShadowedManagedPins(content).some(s => !prot?.has(s.packageName));
  } catch {
    return false;
  }
}

/**
 * Drop managed pins that the platform BOM now manages at or above (they only force older versions),
 * and pins the project's own resolutionStrategy.force already covers (they would silently shadow an
 * explicit decision). Runs on clean exits and nothing-approved breaks too, so a stale block gets
 * cleaned up eventually. Returns true when it rewrote a manifest.
 */
async function cleanupStaleBomPins(projects: ProjectInfo[], bomMaps: Map<string, Map<string, string>>, protectedByProject?: ReadonlyMap<string, ReadonlyMap<string, StaleManagedPin>>): Promise<boolean> {
  if (outputFormat === "json") return false; // machine output stays pure
  const details: Array<{ project: ProjectInfo; stale: StaleManagedPin[]; shadowed: ShadowedManagedPin[] }> = [];
  for (const project of projects) {
    if (project.kind !== "gradle") continue;
    try {
      const content = fs.readFileSync(project.manifestPath, "utf-8");
      const map = bomMaps.get(project.manifestPath);
      // Protected pins (vulnerability escapes) are never dropped as shadowed: the project's own
      // force is itself affected, so our pin — last resolutionStrategy.force wins — keeps it clean.
      const prot = protectedNames(protectedByProject, project);
      const shadowed = findShadowedManagedPins(content).filter(s => !prot?.has(s.packageName));
      const shadowedNames = new Set(shadowed.map(s => s.packageName));
      const stale = (map ? findStaleManagedPins(content, map, prot) : []).filter(s => !shadowedNames.has(s.packageName));
      if (stale.length > 0 || shadowed.length > 0) details.push({ project, stale, shadowed });
    } catch {
      // Unreadable build file — skip.
    }
  }
  if (details.length === 0) return false;
  const list = details.flatMap(d => [
    ...d.stale.map(s => `${s.packageName}@${s.version} (BOM manages ${s.bomVersion})`),
    ...d.shadowed.map(s => `${s.packageName}@${s.version} (project force already pins ${s.userVersion})`),
  ]).join(", ");
  if (dryRun || (!applyFlag && !isTTY)) {
    console.log(`  ~ stale pin(s): ${list} — run with --apply to drop`);
    return false;
  }
  const proceed = applyFlag || await ask(`Drop ${details.reduce((n, d) => n + d.stale.length + d.shadowed.length, 0)} stale managed pin(s)? [y/N] `);
  if (!proceed) return false;
  let changed = false;
  for (const { project } of details) {
    try {
      backupBuildGradle(project.manifestPath);
      const result = applyGradleBumps(project.manifestPath, [], [], bomMaps.get(project.manifestPath) ?? null, protectedNames(protectedByProject, project));
      for (const w of result.warnings) console.log(`  [${project.label}] ${w}`);
      discardGradleBackup(project.manifestPath);
      changed = true;
    } catch {
      restoreBuildGradle(project.manifestPath);
    }
  }
  return changed;
}
function renamesForSourceMigrations(renames: FixCandidate[]): Array<{
  packageName: string;
  renameTo?: string;
  ecosystem?: string;
}> {
  return renames.map(r => ({
    packageName: r.packageName,
    renameTo: r.renameTo,
    ecosystem: r.ecosystem,
  }));
}

function projectEcosystemForKind(kind: FixEcosystem): string {
  switch (kind) {
    case "npm": return "npm";
    case "pypi": return "pypi";
    case "crates.io": return "crates.io";
    default: return "maven";
  }
}

function renamesForProject(
  project: ProjectInfo,
  renames: RenameRequest[],
  findings: Array<{ packageName: string; ecosystem: string }>,
  packages: PackageRef[],
): RenameRequest[] {
  const eco = projectEcosystemForKind(project.kind);
  // Migration-bundled renames carry no finding on the old coordinate; apply them where that coordinate resolves.
  const projectClasspath = new Set(packages.filter(p => p.manifestPath === project.manifestPath).map(p => p.name));
  return renames.filter(r => {
    const findingEco = findings.find(f => f.packageName === r.fromPackage)?.ecosystem;
    if (findingEco !== eco) return !!r.kind && projectClasspath.has(r.fromPackage);
    if (isRootProject(project)) return true;
    return projectDeclaresPackage(project, r.fromPackage);
  });
}

function mapBumps(approved: FixCandidate[]): BumpRequest[] {
  return approved.map(c => ({
    packageName: c.packageName,
    targetVersion: c.targetVersion!,
    because: c.findingIds,
    ecosystem: c.ecosystem,
    isDowngrade: c.isDowngrade === true,
    installedVersion: c.installedVersion,
  }));
}

/** Cross-pass cache of publication checks (same coordinate@version is not re-fetched). */
const publishedVersionCache = new Map<string, boolean | null>();
const isMavenLike = (p: ProjectInfo): p is ProjectInfo & { kind: "maven" | "gradle" } =>
  p.kind === "maven" || p.kind === "gradle";

/** Cross-pass cache of --latest lookups (same coordinate@version is not re-fetched). */
const latestVersionCache = new Map<string, { version: string | null; metadataFound: boolean }>();
/** Coordinate@versions already reported as having no release metadata this run. */
const latestNullLogged = new Set<string>();
/** Cached --latest lookup for one coordinate@installed version (logs missing metadata once per key). */
async function cachedLatestLookup(project: ProjectInfo & { kind: "maven" | "gradle" }, name: string, installed: string): Promise<{ version: string | null; metadataFound: boolean }> {
  const key = `${name}@${installed}`;
  const hit = latestVersionCache.get(key);
  if (hit) return hit;
  const lookup = await findLatestAvailableVersion(project.manifestPath, project.kind, name, installed);
  latestVersionCache.set(key, lookup);
  if (lookup.version === null && !lookup.metadataFound && !latestNullLogged.has(key)) {
    latestNullLogged.add(key);
    console.log(`  [${project.label}] ${name}: no release metadata found — skipping --latest`);
  }
  return lookup;
}

/**
 * Preemptive --latest candidates: for every directly declared Maven/Gradle
 * dependency, the newest non-prerelease release strictly newer than the
 * installed version (per the project's own repository metadata). Coordinates
 * with no advisory finding are included too; already-latest and excluded
 * coordinates produce nothing. Recomputed each pass so applied bumps drop out.
 */
export async function buildLatestCandidates(
  project: ProjectInfo,
  allPackages: Array<{ name: string; version: string }>,
  excludes: Set<string>,
): Promise<FixCandidate[]> {
  if (!isMavenLike(project)) return [];
  let declared: Array<{ name: string; version: string }>;
  try {
    const parsed = project.kind === "gradle"
      ? parseBuildGradleDirect(project.manifestPath)
      : parsePomXmlDirect(project.manifestPath);
    declared = parsed.packages.map(p => ({ name: p.name, version: p.version }));
  } catch {
    return [];
  }

  // Dedupe coordinates, keeping the highest declared version (a managed-block
  // pin can differ from a direct declaration).
  const byCoord = new Map<string, string>();
  for (const d of declared) {
    if (excludes.has(d.name)) continue;
    const prev = byCoord.get(d.name);
    if (prev === undefined || compareMavenVersion(d.version, prev) > 0) byCoord.set(d.name, d.version);
  }

  const out: FixCandidate[] = [];
  for (const [name, declaredVersion] of byCoord) {
    const installed = allPackages.find(p => p.name === name)?.version ?? declaredVersion;
    const lookup = await cachedLatestLookup(project, name, installed);
    if (!lookup.version) continue; // already at the latest release, or metadata unreachable (logged above)
    out.push({
      packageName: name,
      installedVersion: installed,
      targetVersion: lookup.version,
      isMajor: majorOf(lookup.version) !== majorOf(installed),
      findingIds: [],
      severity: "UNKNOWN",
      ecosystem: "maven",
      latest: true,
    });
  }
  return out;
}

/**
 * Merge preemptive --latest candidates into advisory-driven fixable candidates:
 * a coordinate already planned keeps its advisory identity (findingIds, severity)
 * but its target is raised to the newer of advisory/latest; new coordinates are appended.
 */
function mergeLatestCandidates(fixable: FixCandidate[], latest: FixCandidate[]): void {
  for (const lc of latest) {
    const existing = fixable.find(c => c.packageName === lc.packageName && !c.latest);
    if (existing) {
      if (compareMavenVersion(lc.targetVersion!, existing.targetVersion!) > 0) {
        const target = lc.targetVersion!;
        existing.targetVersion = target;
        existing.isMajor = majorOf(target) !== majorOf(existing.installedVersion);
      }
    } else {
      fixable.push(lc);
    }
  }
}

/**
 * Drop maven candidates whose advisory target version is not published in any of the
 * project's repositories. Vendor advisories sometimes claim "fixed" versions that were
 * never released; pinning them breaks resolution for stricter Maven builds. Candidates
 * whose metadata cannot be fetched are kept (best-effort, same as re-targeting).
 */
async function dropUnpublishedTargets(
  candidates: FixCandidate[],
  projects: ProjectInfo[],
  findings: Array<{ packageName: string; ecosystem: string }>,
): Promise<FixCandidate[]> {
  const mavenProject = projects.find(isMavenLike);
  if (!mavenProject) return candidates;

  const kept: FixCandidate[] = [];
  for (const c of candidates) {
    const eco = c.ecosystem ?? findings.find(f => f.packageName === c.packageName)?.ecosystem;
    if (eco !== "maven" || !c.targetVersion) {
      kept.push(c);
      continue;
    }
    const key = `${c.packageName.toLowerCase()}@${c.targetVersion.toLowerCase()}`;
    let published = publishedVersionCache.get(key);
    if (published === undefined) {
      published = await versionPublishedInRepos(mavenProject.manifestPath, mavenProject.kind, c.packageName, c.targetVersion);
      publishedVersionCache.set(key, published);
    }
    if (published === false) {
      console.log(`  ~ skipped: ${c.packageName} — advisory target ${c.targetVersion} is not published in any project repository`);
      continue;
    }
    kept.push(c);
  }
  return kept;
}

function mapRenames(approved: FixCandidate[]): RenameRequest[] {
  return approved
    .filter(c => c.isRename && c.renameTo && c.targetVersion)
    .map(c => ({
      fromPackage: c.packageName,
      toPackage: c.renameTo!,
      targetVersion: c.targetVersion!,
      because: c.findingIds,
      ...(c.consumerVariant ? { kind: "consumerVariant" as const } : c.familyMigrated ? { kind: "familyMigrated" as const } : {}),
    }));
}

type RenameApplyResult = {
  direct?: string[];
  constrained?: string[];
  excluded?: string[];
  warnings: string[];
};

/** How a bundled rename was applied (null = not applied to this project). */
function appliedRenameMethod(
  result: RenameApplyResult,
  candidate: FixCandidate,
): "direct" | "constrained" | "excluded" | null {
  if (!candidate.renameTo) return null;
  const label = `${candidate.packageName} -> ${candidate.renameTo}`;
  if (result.direct?.some(d => d === label || d.startsWith(`${label}:`))) return "direct";
  if (result.constrained?.some(d => d === label || d.startsWith(`${label}:`))) return "constrained";
  if (result.excluded?.includes(candidate.packageName)) return "excluded";
  return null;
}

function dedupeAdvisories<T extends { id: string }>(advisories: T[]): T[] {
  const seen = new Set<string>();
  return advisories.filter(a => {
    if (seen.has(a.id)) return false;
    seen.add(a.id);
    return true;
  });
}

let sessionProjects: ProjectInfo[] = [];
let sessionJavaPaths: string[] = [];

/** Shared mutable state for one fix-loop run (passed to pass helpers). */
interface FixLoopContext {
  resolvedTarget: string;
  projects: ProjectInfo[];
  labels: string[];
  ecoFilters: Set<string>;
  allApplied: AppliedBump[];
  appliedKeys: Set<string>;
  allSourceChanged: string[];
  allSkippedMajors: FixCandidate[];
  allSkippedRenames: FixCandidate[];
  allSkippedUnresolvable: AppliedBump[];
  allRolledBackDowngrades: AppliedBump[];
  sessionUnresolvable: Set<string>;
  approvedExcludeCoords: Set<string>;
  excludeFailedCoords: Set<string>;
  lastUnfixable: FixCandidate[];
  lastFamilyMigrations: FamilyMigrationReport[];
  lastHealthWarnings: string[];
  iteration: number;
  prevFindingSig: string | null;
  prevPlanSig: string | null;
  lastAppliedCount: number;
  findingCountHistory: number[];
  /** True when a manifest moved but the lockfile was not rewritten. Later scans must trust the lock. */
  lockUnsynced: boolean;
  /** True when a Java tree or the GHSA cache was missing, so a zero-finding result is not clean. */
  incompleteScan: boolean;
}

/** Example manifest names for the "no projects found" error (per ecosystem filter). */
function manifestExamplesForFilter(filter: string | null): string {
  if (filter === "npm") return "package.json";
  if (filter === "crates.io") return "Cargo.toml";
  if (filter === "pypi") return "requirements.txt, pyproject.toml";
  if (filter === "maven") return "pom.xml";
  if (filter === "gradle") return "build.gradle, build.gradle.kts";
  return "pom.xml, build.gradle, package.json, Cargo.toml, requirements.txt, pyproject.toml";
}

function failNoProjects(resolvedTarget: string): never {
  if (!fs.existsSync(resolvedTarget)) {
    console.error(`Path not found: ${targetPath}`);
    console.error(`Resolved to: ${resolvedTarget}`);
    const hint = pathHint(targetPath);
    if (hint) console.error(hint);
  } else {
    const supported = ecosystemFilter ? `Supported manifests for '${ecosystemFilter}': ` : "Supported manifests: ";
    console.error(`${supported}${manifestExamplesForFilter(ecosystemFilter)}`);
    console.error(`None found in ${resolvedTarget}.`);
  }
  process.exit(2);
}

interface ScanPassResult {
  findings: Finding[];
  warnings: string[];
  advisories: AdvisoryEntry[];
  packages: PackageRef[];
  unresolved: string[];
}

/**
 * Replace lockfile versions with manifest pins, then re-match so a bump is not
 * still reported only because the lockfile was not regenerated.
 */
function overlayScanResult(
  packages: PackageRef[],
  findings: Finding[],
  advisories: AdvisoryEntry[],
  projectRoot: string,
  extraExcludes: string[] = [],
): { packages: PackageRef[]; findings: Finding[]; overlaid: string[] } {
  const overlay = overlayManifestDirectDeps(packages, projectRoot);
  if (overlay.overlaid.length === 0) return { packages, findings, overlaid: [] };
  const excluded = new Set([...excludeArgs, ...extraExcludes]);
  const rematched = matchVulnerabilities(overlay.packages, advisories)
    .filter(f => !excluded.has(f.packageName));
  return { packages: overlay.packages, findings: rematched, overlaid: overlay.overlaid };
}

/** One scan pass over every project ecosystem, plus per-pass bookkeeping (unresolved set, manifest overlay, warning log). */
async function runScanPass(ctx: FixLoopContext): Promise<ScanPassResult> {
  const result: ScanPassResult = { findings: [], warnings: [], advisories: [], packages: [], unresolved: [] };
  for (const eco of ctx.ecoFilters) {
    const scan = await runAutoBumperScan(ctx.resolvedTarget, {
      ecosystemFilter: eco,
      quietBanner: ctx.iteration > 1,
      ora: defaultSpinnerFactory,
      spinnerPrefix: maxIterations > 1 ? `Pass ${ctx.iteration}/${maxIterations}` : undefined,
      gradleConfigurations: GRADLE_ALL_CONFIGURATIONS,
      offline: offlineFlag,
      excludePackages: [...excludeArgs, ...ctx.approvedExcludeCoords],
    });
    result.findings.push(...scan.findings);
    result.warnings.push(...scan.warnings);
    result.advisories.push(...scan.advisories);
    result.packages.push(...scan.packages);
    for (const u of scan.unresolved ?? []) {
      if (!result.unresolved.includes(u)) result.unresolved.push(u);
    }
    if (scan.incomplete) ctx.incompleteScan = true;
  }
  // Remember every coordinate the build could not resolve — never re-apply a fix targeting it.
  for (const u of result.unresolved) ctx.sessionUnresolvable.add(u);

  if (ctx.iteration > 1 && !ctx.lockUnsynced) {
    const overlay = overlayScanResult(result.packages, result.findings, result.advisories, ctx.resolvedTarget, [...ctx.approvedExcludeCoords]);
    result.packages = overlay.packages;
    result.findings = overlay.findings;
    if (overlay.overlaid.length > 0) console.log(`  ${MANIFEST_OVERLAY_WARNING}`);
  } else if (ctx.iteration > 1 && ctx.lockUnsynced) {
    console.log("  Lockfile was not updated. Scan uses the lockfile, not the manifest.");
  }

  for (const w of Array.from(new Set(result.warnings))) console.log(`  ${w}`);

  if (result.packages.length === 0) {
    console.error("No packages scanned — ecosystem filter matched nothing or dependency resolution failed.");
    process.exit(2);
  }
  return result;
}

/** Report a clean run and exit (all findings fixed, rolled-back fixes, or nothing to do). */
function reportCleanExit(ctx: FixLoopContext): never {
  if (ctx.incompleteScan) {
    console.error("Scan incomplete: dependency tree or advisory data was not fully loaded. Not reporting a clean result.");
    process.exit(2);
  }
  // Successfully excluded packages are reported in the Applied section — do not re-list them as unfixable.
  const unfixableShown = ctx.lastUnfixable.filter(u => !ctx.approvedExcludeCoords.has(u.packageName));
  if (outputFormat === "json") {
    console.log(JSON.stringify({ status: "clean", applied: ctx.allApplied, skippedMajors: ctx.allSkippedMajors, skippedUnresolvable: ctx.allSkippedUnresolvable, rolledBackDowngrades: ctx.allRolledBackDowngrades }, null, 2));
  } else if (ctx.allSkippedUnresolvable.length > 0 || ctx.allRolledBackDowngrades.length > 0) {
    console.log(planMarkdown({ fixable: [], unfixable: [], renames: [], downgrades: [] }, { applied: ctx.allApplied, unfixableRemaining: unfixableShown, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: null, skippedSourceMigrations: false, skippedUnresolvable: ctx.allSkippedUnresolvable }));
    if (ctx.allSkippedUnresolvable.length > 0) console.log(`Remaining issues: ${ctx.allSkippedUnresolvable.length} fix(es) rolled back — target version not resolvable from project repositories.`);
    if (ctx.allRolledBackDowngrades.length > 0) console.log(`Remaining issues: ${ctx.allRolledBackDowngrades.length} downgrade(s) rolled back — build failed after downgrade; original versions kept.`);
  } else if (ctx.allApplied.length > 0) {
    console.log(planMarkdown({ fixable: [], unfixable: [], renames: [], downgrades: [] }, { applied: ctx.allApplied, unfixableRemaining: unfixableShown, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: null, skippedSourceMigrations: false }));
    console.log("All vulnerabilities fixed.");
  } else {
    console.log("No vulnerabilities found.");
  }
  for (const p of ctx.projects) discardManifestBackup(p);
  discardSourceMigrationBackups(ctx.allSourceChanged);
  process.exit((ctx.allSkippedUnresolvable.length > 0 || ctx.allRolledBackDowngrades.length > 0) && strictExit ? 1 : 0);
}

/** Plan + gate decisions for one pass. */
interface PassPlan {
  plan: FixPlan;
  approved: FixCandidate[];
  skippedMajors: FixCandidate[];
  approvedRenames: FixCandidate[];
  skippedRenames: FixCandidate[];
  effectiveApproved: FixCandidate[];
  effectiveRenames: FixCandidate[];
  effectiveExcludes: FixCandidate[];
  policy: RenameApplyPolicy;
}

/** True when `version` is still affected by any advisory that names this package — a proposed target must escape all of them. */
function isUnsafeFor(advisories: AdvisoryEntry[], candidate: FixCandidate, eco: string): (version: string) => boolean {
  const entries = packageAdvisoryEntries(advisories, candidate.packageName, eco);
  return (version: string) => entries.some(e => isVersionAffected(candidate.packageName, version, eco, e));
}

/** When OSV only has last_affected, pin a published GA release that escapes every affected window of the package. */
async function promoteLastAffectedFixes(
  plan: FixPlan,
  projects: ProjectInfo[],
  advisories: AdvisoryEntry[],
  versionsFor: (packageName: string) => Promise<string[] | null>,
): Promise<void> {
  const project = projects.find(isMavenLike);
  if (!project || offlineFlag) return;
  const still: FixCandidate[] = [];
  for (const candidate of plan.unfixable) {
    if ((candidate.ecosystem || "maven") !== "maven" || !candidate.lastAffected) {
      still.push(candidate);
      continue;
    }
    const eco = candidate.ecosystem || "maven";
    const versions = await versionsFor(candidate.packageName);
    const safe = versions ? pickSafeEscapeVersion(versions, candidate.installedVersion, "up", eco, isUnsafeFor(advisories, candidate, eco)) : null;
    const promoted = withNextFixVersion(candidate, safe);
    if (!promoted) {
      // introduced set → the downgrade pass below reports the consolidated unsatisfiable verdict.
      if (!candidate.introduced) console.log(`  ~ ${candidate.packageName}: last affected ${candidate.lastAffected}, no published release after it`);
      still.push(candidate);
      continue;
    }
    console.log(`  ~ ${candidate.packageName}: last affected ${candidate.lastAffected}, using next published ${promoted.targetVersion}`);
    plan.fixable.push(promoted);
  }
  plan.unfixable = still;
}

/**
 * Co-versioned-family gate for cross-major downgrades. A downgrade that moves a family member to
 * another major line splits the family unless every classpath sibling moves with it. A sibling
 * pinned by the project's own resolutionStrategy.force on another line makes the move unsafe —
 * refuse. The candidate's own such pin is respected only when the pinned version is not affected:
 * a managed force written after the project's forces wins (last-wins in Gradle), so a pin to an
 * affected version does not make the split permanent — that is the escape-pin case, and only the
 * candidate moves (siblings stay on their line; no advisory requires moving them). Otherwise each
 * sibling is pulled along to the newest safe GA release on the target line, preferring the
 * primary's exact version when published for that artifact.
 */
export async function downgradeFamilyGate(
  familyName: string,
  candidate: FixCandidate,
  targetVersion: string,
  classpath: ReadonlyArray<{ packageName: string; installedVersion: string; ecosystem: string }>,
  manifestPath: string,
  advisories: AdvisoryEntry[],
  versionsFor: (packageName: string) => Promise<string[] | null>,
): Promise<{ refuse: string } | { pullAlong: FixCandidate[]; note?: string }> {
  const targetMajor = majorOf(targetVersion);
  let userForces: Map<string, string> | undefined;
  const loadUserForces = (): Map<string, string> => {
    if (!userForces) userForces = parseUserForces(fs.readFileSync(manifestPath, "utf-8"));
    return userForces;
  };
  const selfPin = loadUserForces().get(candidate.packageName);
  if (selfPin !== undefined && majorOf(selfPin) !== targetMajor) {
    if (!isVersionAffectedByAdvisories(candidate.packageName, selfPin, "maven", advisories)) {
      return { refuse: `the project pins ${candidate.packageName} itself via its own resolutionStrategy.force at ${selfPin}` };
    }
    return { pullAlong: [], note: `escape pin: overriding the project's own force at ${selfPin} (last resolutionStrategy.force wins; the pinned version is affected)` };
  }
  const pullAlong: FixCandidate[] = [];
  const siblings = classpath.filter(
    p => p.ecosystem === "maven" && p.packageName !== candidate.packageName && familyOf(p.packageName)?.name === familyName && majorOf(p.installedVersion) !== targetMajor,
  );
  for (const sib of siblings) {
    const pin = loadUserForces().get(sib.packageName);
    if (pin !== undefined && majorOf(pin) !== targetMajor) {
      return { refuse: `sibling ${sib.packageName} is pinned by the project's own resolutionStrategy.force at ${pin}` };
    }
    const versions = await versionsFor(sib.packageName);
    if (!versions) return { refuse: `cannot verify published releases for sibling ${sib.packageName}` };
    const unsafe = isUnsafeFor(advisories, { ...candidate, packageName: sib.packageName }, "maven");
    const line = versions.filter(v => majorOf(v) === targetMajor && !isPreReleaseOrSnapshot(v) && !unsafe(v));
    if (line.length === 0) return { refuse: `no safe ${targetMajor}.x release exists for sibling ${sib.packageName}` };
    const chosen = line.find(v => compareMavenVersion(v, targetVersion) === 0) ?? line.reduce((a, b) => (compareMavenVersion(a, b) >= 0 ? a : b));
    pullAlong.push({
      packageName: sib.packageName,
      installedVersion: sib.installedVersion,
      targetVersion: chosen,
      isMajor: true,
      findingIds: candidate.findingIds,
      severity: candidate.severity,
      ecosystem: "maven",
      isDowngrade: true,
    });
  }
  return { pullAlong };
}

/** When OSV has no forward fix, a published GA release below the installed one that escapes every affected window fixes the finding. */
async function promoteDowngradeFixes(
  plan: FixPlan,
  projects: ProjectInfo[],
  advisories: AdvisoryEntry[],
  versionsFor: (packageName: string) => Promise<string[] | null>,
  classpath: ReadonlyArray<{ packageName: string; installedVersion: string; ecosystem: string }>,
): Promise<void> {
  const project = projects.find(isMavenLike);
  if (!project || offlineFlag) return;
  const still: FixCandidate[] = [];
  for (const candidate of plan.unfixable) {
    if ((candidate.ecosystem || "maven") !== "maven" || !candidate.introduced) {
      still.push(candidate);
      continue;
    }
    const eco = candidate.ecosystem || "maven";
    const versions = await versionsFor(candidate.packageName);
    const safe = versions ? pickSafeEscapeVersion(versions, candidate.installedVersion, "down", eco, isUnsafeFor(advisories, candidate, eco)) : null;
    const promoted = withDowngradeVersion(candidate, safe);
    if (!promoted) {
      if (candidate.lastAffected && versions) {
        console.log(`  ~ ${candidate.packageName}: unsatisfiable — no published GA version escapes all affected windows (introduced ${candidate.introduced}, last_affected ${candidate.lastAffected}); manual decision required`);
      } else {
        console.log(`  ~ ${candidate.packageName}: no published release below introduced ${candidate.introduced}`);
      }
      still.push(candidate);
      continue;
    }
    // Co-versioned-family gate: a cross-major downgrade must not leave family siblings on the old line.
    let pullAlong: FixCandidate[] = [];
    const fam = familyOf(candidate.packageName);
    if (fam && majorOf(promoted.targetVersion!) !== majorOf(candidate.installedVersion)) {
      const gate = await downgradeFamilyGate(fam.name, candidate, promoted.targetVersion!, classpath, project.manifestPath, advisories, versionsFor);
      if ("refuse" in gate) {
        console.log(`  ~ ${candidate.packageName}: no forward fix; downgrade to ${promoted.targetVersion} refused — ${gate.refuse}`);
        still.push({ ...candidate, familyClamped: `downgrade to ${promoted.targetVersion!} would split family '${fam.name}': ${gate.refuse}` });
        continue;
      }
      pullAlong = gate.pullAlong;
      if (gate.note) console.log(`  ~ ${candidate.packageName}: ${gate.note}`);
    }
    if (allowDowngrades) {
      console.log(`  ~ ${candidate.packageName}: no forward fix; downgrading to ${promoted.targetVersion} (escapes all affected windows)${promoted.isMajor ? ` — crosses major boundary, gated by --allow-major` : ""}`);
      plan.downgrades.push(promoted, ...pullAlong);
      for (const sib of pullAlong) console.log(`  ~ ${sib.packageName}: moved with ${candidate.packageName} downgrade — ${sib.installedVersion} -> ${sib.targetVersion}`);
    } else {
      const siblings = pullAlong.length > 0 ? `; would also move ${pullAlong.map(s => `${s.packageName} ${s.installedVersion} -> ${s.targetVersion}`).join(", ")}` : "";
      console.log(`  ~ ${candidate.packageName}: no forward fix; safe downgrade target ${promoted.targetVersion} available (escapes all affected windows)${siblings} — pass --allow-downgrades to apply it`);
      still.push({ ...candidate, downgradeTarget: promoted.targetVersion! });
    }
  }
  plan.unfixable = still;
}

/**
 * Co-versioned families (jetty, netty, vertx, jackson) that are stuck get a coherent whole-family
 * move: pin every classpath member to a single published GA version on the newest installed line
 * or a higher line where no member is affected by any advisory. A family is stuck when an affected
 * member has no fixable candidate, a guard-clamped/demoted candidate, or a target that is not
 * published in any project repository (e.g. the 11.x line went EOL below its own minimal fix).
 * Maven only — Gradle coordinates the family through BOMs/platforms instead of pins.
 */
async function applyFamilyMigrations(
  plan: FixPlan,
  projects: ProjectInfo[],
  advisories: AdvisoryEntry[],
  versionsFor: (packageName: string) => Promise<string[] | null>,
  classpath: ReadonlyArray<{ packageName: string; installedVersion: string; ecosystem: string }>,
  findings: Finding[],
  packages: PackageRef[],
): Promise<FamilyMigrationReport[]> {
  const project = projects.find(isMavenLike);
  if (!project || offlineFlag) return [];
  const migrations = planFamilyMigrations(classpath, findings);
  if (migrations.length === 0) return [];
  for (const mg of migrations) {
    console.log(`  ~ family '${mg.familyName}': ${mg.memberPackages.length} members — ${mg.memberPackages.join(", ")}`);
  }

  const reports: FamilyMigrationReport[] = [];
  for (const mig of migrations) {
    const memberSet = new Set(mig.memberPackages);
    const installedOf = new Map<string, string>();
    for (const p of classpath) if (memberSet.has(p.packageName)) installedOf.set(p.packageName, p.installedVersion);
    const findingIdsOf = new Map<string, string[]>();
    for (const f of findings) {
      if (!memberSet.has(f.packageName)) continue;
      const ids = findingIdsOf.get(f.packageName) ?? [];
      ids.push(f.id);
      findingIdsOf.set(f.packageName, ids);
    }

    const lists = await Promise.all(mig.memberPackages.map(m => versionsFor(m)));
    if (lists.some(l => l === null)) continue; // metadata unavailable — keep per-artifact verdicts
    const listSets = lists.map(l => new Set(l!));

    // Members whose coordinate was renamed upstream (e.g. Jetty 12's http2-* -> jetty-http2-*)
    // can still migrate when the old coordinate no longer publishes on the target line.
    const successorOf = new Map<string, string>();
    for (const m of mig.memberPackages) {
      const s = KNOWN_RENAMES[m];
      if (s) successorOf.set(m, s);
    }
    const successors = [...new Set(successorOf.values())];
    const succLists = await Promise.all(successors.map(s => versionsFor(s)));
    if (succLists.some(l => l === null)) continue; // metadata unavailable — keep per-artifact verdicts
    const succSets = new Map(successors.map((s, i) => [s, new Set(succLists[i]!)]));
    // Stuck? An affected member whose candidate is missing, guard-clamped, or targets an
    // unpublished version cannot be fixed by the per-artifact flow.
    const stuck = mig.memberPackages.some((m, i) => {
      if (!findingIdsOf.has(m)) return false;
      const c = plan.fixable.find(x => x.packageName === m && (x.ecosystem || "maven") === "maven");
      if (!c || c.targetVersion === null) return true;
      if (c.familyClamped) return true;
      return !listSets[i].has(c.targetVersion);
    });
    if (!stuck) continue; // per-artifact flow already handles this family

    const unsafeAt = new Map<string, (v: string) => boolean>();
    for (const m of mig.memberPackages) {
      const successor = successorOf.get(m);
      const entries = packageAdvisoryEntries(advisories, m, "maven");
      const succEntries = successor ? packageAdvisoryEntries(advisories, successor, "maven") : [];
      unsafeAt.set(m, v =>
        entries.some(e => isVersionAffected(m, v, "maven", e)) ||
        succEntries.some(e => isVersionAffected(successor!, v, "maven", e)),
      );
    }

    let target: string | null = null;
    let participating: string[] = [];
    for (const lineMajor of mig.linesToTry) {
      // Members available on this line: the own list while it still publishes there, otherwise
      // the renamed successor's list. Discontinued members (e.g. Jetty 12 dropped the alpn
      // modules) have no version on the line and stay at their current version.
      const effective = new Map<string, Set<string>>();
      mig.memberPackages.forEach((m, i) => {
        const ownHasLine = [...listSets[i]].some(v => majorOf(v) === lineMajor && !isPreReleaseOrSnapshot(v));
        if (ownHasLine) { effective.set(m, listSets[i]); return; }
        const s = successorOf.get(m);
        if (s) effective.set(m, succSets.get(s)!);
      });
      const membersOnLine = [...effective.keys()];
      if (membersOnLine.length === 0) continue; // no member publishes on this line at all
      const lineSets = membersOnLine.map(m => effective.get(m)!);
      const common: string[] = [];
      for (const v of lineSets[0]!) {
        if (majorOf(v) !== lineMajor || isPreReleaseOrSnapshot(v)) continue;
        if (lineSets.every(s => s.has(v))) common.push(v);
      }
      common.sort((a, b) => compareMavenVersion(a, b));
      for (const v of common) {
        if (membersOnLine.every(m => !unsafeAt.get(m)!(v))) { target = v; break; }
      }
      if (!target && common.length > 0) {
        const blocker = membersOnLine.find(m => unsafeAt.get(m)!(common[common.length - 1]));
        console.log(`  ~ family '${mig.familyName}': line ${lineMajor}: ${common.length} common version(s), none clears all advisories${blocker ? ` — ${blocker} still affected at ${common[common.length - 1]}` : ""}`);
      }
      if (target) { participating = membersOnLine; break; }
    }

    if (!target) {
      console.log(`  ~ family '${mig.familyName}': no published release line clears all advisories — keeping per-artifact verdicts`);
      continue;
    }
    // Participating members whose own coordinate no longer publishes on the target line migrate via rename.
    const renamedOf = new Map<string, string>();
    for (const m of participating) {
      const i = mig.memberPackages.indexOf(m);
      const s = successorOf.get(m);
      if (!s) continue;
      const ownHasTargetLine = [...listSets[i]].some(v => majorOf(v) === majorOf(target!) && !isPreReleaseOrSnapshot(v));
      if (!ownHasTargetLine) renamedOf.set(m, s);
    }
    if (renamedOf.size > 0 && !allowRenames) {
      console.log(`  ~ family '${mig.familyName}': migration to ${target} requires coordinate renames (${[...renamedOf.entries()].map(([f, t]) => `${f} -> ${t}`).join(", ")}) — pass --allow-renames to proceed`);
      continue;
    }
    const crossMajor = participating.some(m => majorOf(target) !== majorOf(installedOf.get(m)!));
    console.log(`  ~ family '${mig.familyName}': migrating ${participating.length} of ${mig.memberPackages.length} artifacts to ${target}${crossMajor ? " (cross-major, gated by --allow-major)" : ""}${participating.length < mig.memberPackages.length ? `; ${mig.memberPackages.length - participating.length} member(s) have no version on this line and stay put` : ""}`);

    for (const m of participating) {
      const installed = installedOf.get(m)!;
      const findingIds = findingIdsOf.get(m) ?? [];
      const isMajor = majorOf(target) !== majorOf(installed);
      const successor = renamedOf.get(m);
      if (successor) {
        // The old coordinate dies on this line: emit a rename candidate instead of a pin.
        plan.fixable = plan.fixable.filter(c => !(c.packageName === m && (c.ecosystem || "maven") === "maven"));
        const reason = `family '${mig.familyName}' migrated to ${successor} @ ${target} for coherence`;
        const existing = plan.renames.find(c => c.packageName === m && (c.ecosystem || "maven") === "maven");
        if (existing) {
          existing.renameTo = successor;
          existing.targetVersion = target;
          existing.isMajor = isMajor;
          existing.findingIds = findingIds;
          delete existing.familyClamped;
          delete existing.sameMajorTarget;
          existing.familyMigrated = reason;
        } else {
          plan.renames.push({
            packageName: m,
            installedVersion: installed,
            targetVersion: target,
            isMajor,
            findingIds,
            severity: "UNKNOWN",
            ecosystem: "maven",
            renameTo: successor,
            isRename: true,
            familyMigrated: reason,
          });
        }
        continue;
      }
      const reason = `family '${mig.familyName}' pinned to ${target} for coherence`;
      const existing = plan.fixable.find(c => c.packageName === m && (c.ecosystem || "maven") === "maven");
      if (existing) {
        existing.targetVersion = target;
        existing.isMajor = isMajor;
        existing.findingIds = findingIds;
        delete existing.familyClamped;
        delete existing.sameMajorTarget;
        existing.familyMigrated = reason;
      } else {
        plan.fixable.push({
          packageName: m,
          installedVersion: installed,
          targetVersion: target,
          isMajor,
          findingIds,
          severity: "UNKNOWN",
          ecosystem: "maven",
          familyMigrated: reason,
        });
      }
    }
    // Consumer artifacts with ecosystem-specific builds must move to the matching variant, otherwise
    // stripping their old transitive coordinates leaves them without an implementation layer.
    const swappedVariants: Record<string, string> = {};
    for (const variant of consumerVariantsForFamily(mig.familyName)) {
      const installed = classpath.find(p => p.packageName === variant.from)?.installedVersion;
      if (!installed) continue;
      if (classpath.some(p => p.packageName === variant.to)) continue; // already on the migrated variant
      // Only a direct dependency of the project (top-level in the resolved tree) can be swapped in place.
      if (!topLevelAncestors(variant.from, packages).has(variant.from)) continue;
      const reason = `consumer variant: ${variant.from} -> ${variant.to} for family '${mig.familyName}' coherence`;
      const existing = plan.renames.find(c => c.packageName === variant.from && (c.ecosystem || "maven") === "maven");
      if (existing) {
        existing.renameTo = variant.to;
        existing.targetVersion = installed;
        existing.isMajor = false;
        delete existing.familyClamped;
        delete existing.sameMajorTarget;
        existing.familyMigrated = reason;
        existing.consumerVariant = true;
      } else {
        plan.renames.push({
          packageName: variant.from,
          installedVersion: installed,
          targetVersion: installed, // the variant publishes the same version line
          isMajor: false,
          findingIds: [],
          severity: "UNKNOWN",
          ecosystem: "maven",
          renameTo: variant.to,
          isRename: true,
          familyMigrated: reason,
          consumerVariant: true,
        });
      }
      swappedVariants[variant.from] = variant.to;
    }
    // Demoted (unfixable) copies of migrating members are now fixable through the migration.
    const migratingSet = new Set(participating);
    plan.unfixable = plan.unfixable.filter(c => !migratingSet.has(c.packageName) || (c.ecosystem || "maven") !== "maven");
    reports.push({ family: mig.familyName, targetVersion: target, memberCount: participating.length, renamedMembers: Object.fromEntries(renamedOf), consumerVariants: swappedVariants });
  }
  return reports;
}

async function buildPassPlan(ctx: FixLoopContext, scan: ScanPassResult, latestCandidates: FixCandidate[]): Promise<PassPlan> {
  const advisories = dedupeAdvisories(scan.advisories);
  const classpath = scan.packages.map(p => ({ packageName: p.name, installedVersion: p.version, ecosystem: p.ecosystem }));
  const plan = buildFixPlan(scan.findings, advisories, classpath);
  const versionLists = new Map<string, Promise<string[] | null>>();
  const versionsFor = (packageName: string): Promise<string[] | null> => {
    let pending = versionLists.get(packageName);
    if (!pending) {
      const project = ctx.projects.find(isMavenLike);
      pending = project ? listAvailableVersions(project.manifestPath, project.kind, packageName) : Promise.resolve(null);
      versionLists.set(packageName, pending);
    }
    return pending;
  };
  await promoteLastAffectedFixes(plan, ctx.projects, advisories, versionsFor);
  await promoteDowngradeFixes(plan, ctx.projects, advisories, versionsFor, classpath);
  ctx.lastFamilyMigrations = await applyFamilyMigrations(plan, ctx.projects, advisories, versionsFor, classpath, scan.findings, scan.packages);
  plan.renames = expandRenameBundle(plan.renames, scan.packages);
  if (latestFlag && latestCandidates.length > 0) mergeLatestCandidates(plan.fixable, latestCandidates);

  const healthWarnings = Array.from(new Set([
    ...analyzeFixPlan(plan, scan.packages),
    ...ctx.projects.filter(p => p.kind === "gradle").flatMap(p => analyzeBuildGradleFile(p.manifestPath)),
  ]));
  if (sourceMigrationsForAppliedRenames(renamesForSourceMigrations(plan.renames)) && !allowSourceMigrations) {
    healthWarnings.push("Coordinate rename may break compile until source is updated — see Planned source migrations in dry-run, or pass --allow-source-migrations (requires --allow-renames).");
  }
  for (const w of healthWarnings) console.log(`  ! ${w}`);
  ctx.lastHealthWarnings = healthWarnings;
  ctx.lastUnfixable = plan.unfixable;
  // Approved here; promoted to approvedExcludeCoords only after runApplyPass verifies every touched project wrote the exclusion.
  const { approved: effectiveExcludes, warnings: excludeGateWarnings } = await filterByExcludeGate(plan.unfixable, ctx.projects, ctx.approvedExcludeCoords, ctx.excludeFailedCoords, scan.packages, forceExcludeCoords);
  for (const w of excludeGateWarnings) console.log(`  ! ${w}`);
  if (excludeGateWarnings.length > 0) ctx.lastHealthWarnings.push(...excludeGateWarnings);

  const { approved, skipped } = await filterByMajorGate(plan.fixable);
  ctx.allSkippedMajors.push(...skipped);
  const { approved: approvedRenames, skipped: skippedRenames } = await filterByRenameGate(plan.renames);
  ctx.allSkippedRenames.push(...skippedRenames);

  const manifestPaths = ctx.projects.map(p => p.manifestPath);
  const filtered = filterRedundantFixes(approved, approvedRenames, scan.packages, manifestPaths);
  for (const s of filtered.skipped) console.log(`  ~ skipped: ${s}`);
  let effectiveApproved: FixCandidate[] = dropUnresolvable(filtered.fixable, ctx.sessionUnresolvable);
  let effectiveRenames: FixCandidate[] = dropUnresolvable(filtered.renames, ctx.sessionUnresolvable);
  if (effectiveRenames.length === 0) {
    effectiveRenames = dropUnresolvable(renamesForMixedClasspathCompletion(approvedRenames, scan.packages), ctx.sessionUnresolvable);
  }
  effectiveApproved = await dropUnpublishedTargets(effectiveApproved, ctx.projects, scan.findings);
  const { approved: downgradeApproved, skipped: skippedDowngrades } = await filterByMajorGate(plan.downgrades, "downgrade");
  ctx.allSkippedMajors.push(...skippedDowngrades);
  if (downgradeApproved.length > 0) effectiveApproved = [...effectiveApproved, ...dropUnresolvable(downgradeApproved, ctx.sessionUnresolvable)];
  const policy = applyPolicyForRenames(effectiveRenames.map(r => ({ fromPackage: r.packageName, toPackage: r.renameTo ?? "" })));
  return { plan, approved, skippedMajors: skipped, approvedRenames, skippedRenames, effectiveApproved, effectiveRenames, effectiveExcludes, policy };
}

/** Nothing left to apply this pass: report and exit, or stop the loop when gates blocked real work. Returns true when the caller must break. */
function handleNothingApproved(ctx: FixLoopContext, pass: PassPlan, findingCount: number): boolean {
  if (pass.approved.length > 0 || pass.approvedRenames.length > 0) {
    console.log(fixLoopBlockedMessage({
      findingCount,
      skippedMajors: pass.skippedMajors.length,
      skippedRenames: pass.skippedRenames.length,
      skippedSourceBoundRenames: pass.skippedRenames.filter(r => renameNeedsSourceMigration(r)).length,
    }));
    return true;
  }
  const showPlan = dryRun && (pass.plan.fixable.length > 0 || pass.plan.downgrades.length > 0 || pass.plan.renames.length > 0);
  if (showPlan) {
    console.log(planMarkdown(pass.plan, { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: sourceMigrationsForAppliedRenames(renamesForSourceMigrations(pass.plan.renames)), excludeFailed: ctx.excludeFailedCoords }));
    process.exit(0);
  }
  console.log(planMarkdown({ ...pass.plan, fixable: [] }, { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: null, skippedSourceMigrations: false, skippedUnresolvable: ctx.allSkippedUnresolvable, excludeFailed: ctx.excludeFailedCoords }));
  console.log("Nothing to apply.");
  if (pass.skippedMajors.length > 0) console.log(`  - ${pass.skippedMajors.length} major version change(s) skipped — approve at prompt, or use --allow-major`);
  if (pass.skippedRenames.length > 0) console.log(`  - ${pass.skippedRenames.length} rename(s) skipped — approve at prompt, or use --allow-renames`);
  if (pass.plan.unfixable.length > 0) console.log(`  - ${pass.plan.unfixable.length} package(s) have no OSV fix version — use --exclude=group:artifact to ignore, or re-run with --apply-excludes to exclude them from the dependency graph`);
  if (applyExcludes && pass.plan.unfixable.length > 0 && !ctx.projects.some(isMavenLike)) console.log("  - exclusions need a Maven/Gradle manifest — nothing to apply");
  process.exit(dryRun || !strictExit ? 0 : 1);
}

/** Fix-loop stop gate. `includeCap` selects the pre-plan checks (cap/stall/oscillation) vs post-plan (stall/oscillation only). */
function loopStopped(ctx: FixLoopContext, findingCount: number, findingSig: string, includeCap: boolean, planSig?: string, prevPlanSig?: string | null): boolean {
  const stopReason = fixLoopStopReason({
    findingCount,
    findingSig,
    prevFindingSig: ctx.prevFindingSig,
    iteration: ctx.iteration,
    maxIterations,
    lastAppliedCount: ctx.lastAppliedCount,
    findingCountHistory: ctx.findingCountHistory,
    planSig,
    prevPlanSig,
  });
  if (stopReason === null) return false;
  const stop = includeCap
    ? stopReason === "cap" || stopReason === "stall" || stopReason === "oscillation"
    : stopReason === "stall" || stopReason === "oscillation";
  if (!stop) return false;
  console.log(fixLoopStopMessage(stopReason, { findingCount, maxIterations }));
  return true;
}

/** Preemptive --latest candidates across all projects (empty when --latest is off). */
async function buildLatestForProjects(ctx: FixLoopContext, packages: PackageRef[]): Promise<FixCandidate[]> {
  if (!latestFlag) return [];
  const excludedPkgs = new Set(excludeArgs);
  return (await Promise.all(ctx.projects.map(p => buildLatestCandidates(p, packages, excludedPkgs)))).flat();
}

/** Source migrations that would run if this pass applied (for dry-run reporting; null when none planned). */
function plannedSourceMigrationsFor(pass: PassPlan): SourceMigrationConfig | null {
  let renames: FixCandidate[];
  if (dryRun) renames = pass.plan.renames;
  else if (pass.effectiveRenames.length > 0) renames = pass.effectiveRenames;
  else renames = pass.plan.renames;
  return sourceMigrationsForAppliedRenames(renamesForSourceMigrations(renames));
}

interface ApplyBatch {
  bumps: BumpRequest[];
  renames: RenameRequest[];
  effectiveApproved: FixCandidate[];
  effectiveRenames: FixCandidate[];
  effectiveExcludes: FixCandidate[];
  excludes: Array<{ packageName: string; attachTo?: string[] }>;
  findings: Finding[];
  packages: PackageRef[];
}

/** Build the apply batch for one pass (policy pins, rename requests, exclude coordinates). */
function buildApplyBatch(pass: PassPlan, findings: Finding[], packages: PackageRef[]): ApplyBatch {
  let bumps = mapBumps(pass.effectiveApproved).filter(b => !pass.policy.rejectPins.has(b.packageName));
  for (const p of pass.policy.extraPins) {
    if (!bumps.some(b => b.packageName === p.packageName)) {
      bumps.push({ packageName: p.packageName, targetVersion: p.version, because: ["migration-policy"] });
    }
  }
  const renames = mapRenames(pass.effectiveRenames);
  // Old coordinates of migrated families are excluded from the configurations that still pull them in —
  // unless a consumer-variant swap already removes them from the classpath entirely.
  const swappedConsumers = new Set(pass.effectiveRenames.filter(r => r.consumerVariant).map(r => r.packageName));
  const oldCoordExcludes: Array<{ packageName: string; attachTo?: string[] }> = [];
  if (pass.policy.excludeOldCoordinates) {
    for (const r of pass.effectiveRenames) {
      if (r.consumerVariant) continue; // its from-coordinate is removed by the swap itself
      if (!packages.some(p => p.name === r.packageName)) continue; // no longer on the resolved classpath
      const sources = topLevelAncestors(r.packageName, packages);
      if (sources.size > 0 && [...sources].every(s => swappedConsumers.has(s))) {
        console.log(`  ~ exclusion of ${r.packageName} not needed — all sources (${[...sources].join(", ")}) are being swapped to a migrated variant`);
        continue;
      }
      oldCoordExcludes.push({ packageName: r.packageName, attachTo: sources.size > 0 ? [...sources] : undefined });
    }
  }
  const excludes = [
    ...excludeArgs.map(coord => ({ packageName: coord })),
    ...pass.effectiveExcludes.filter(c => !excludeArgs.includes(c.packageName)).map(c => ({ packageName: c.packageName })),
    ...oldCoordExcludes,
  ];
  return { bumps, renames, effectiveApproved: pass.effectiveApproved, effectiveRenames: pass.effectiveRenames, effectiveExcludes: pass.effectiveExcludes, excludes, findings, packages };
}

function isRootProject(project: ProjectInfo): boolean {
  const dir = path.dirname(project.manifestPath);
  return !sessionProjects.some(other =>
    other.kind === project.kind && path.dirname(other.manifestPath).length < dir.length,
  );
}

function projectDeclaresPackage(project: ProjectInfo, packageName: string): boolean {
  if (project.kind === "maven" || project.kind === "gradle") return projectDeclaresCoord(project, packageName);
  let text: string;
  try {
    text = fs.readFileSync(project.manifestPath, "utf-8");
  } catch {
    return false;
  }
  if (project.kind === "npm") {
    try {
      const data = JSON.parse(text) as Record<string, unknown>;
      for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
        const deps = data[section];
        if (deps && typeof deps === "object" && packageName in (deps as Record<string, unknown>)) return true;
      }
    } catch {
      return false;
    }
    return false;
  }
  if (project.kind === "crates.io") {
    const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`^\\s*${escaped}\\s*=`, "m").test(text);
  }
  const norm = packageName.toLowerCase().replace(/[_\s]+/g, "-");
  return text.split(/\r?\n/).some(line => {
    const quoted = /["']([A-Za-z0-9_.-]+)/.exec(line);
    const plain = /^\s*([A-Za-z0-9_.-]+)\s*(===|==|>=|<=|~=|!=|>|<|=)/.exec(line);
    const name = (quoted?.[1] ?? plain?.[1] ?? "").toLowerCase().replace(/[_\s]+/g, "-");
    return name === norm;
  });
}

function projectDeclaresCoord(project: ProjectInfo, coord: string): boolean {
  let text: string;
  try {
    text = fs.readFileSync(project.manifestPath, "utf-8");
  } catch {
    return false;
  }
  const [group, artifact] = coord.split(":");
  if (!group || !artifact) return text.includes(coord);
  if (text.includes(`${group}:${artifact}`)) return true;
  if (project.kind !== "maven") return false;
  const blocks = text.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
  return blocks.some(block =>
    block.includes(`<groupId>${group}</groupId>`) && block.includes(`<artifactId>${artifact}</artifactId>`),
  );
}

/** Bumps belonging to one project (maven/gradle share the maven ecosystem). */
function bumpsForProject(project: ProjectInfo, batch: ApplyBatch): BumpRequest[] {
  return batch.bumps.filter(b => {
    const pkgEco = b.ecosystem ?? batch.findings.find(f => f.packageName === b.packageName)?.ecosystem;
    if (project.kind === "maven" || project.kind === "gradle") {
      if (pkgEco !== "maven") return false;
      if (isRootProject(project)) return true;
      return projectDeclaresCoord(project, b.packageName);
    }
    if (pkgEco !== project.kind) return false;
    if (isRootProject(project)) return true;
    return projectDeclaresPackage(project, b.packageName);
  });
}

interface ProjectApplyOutcome { direct: number; constrained: number; fileChanges: number; renamed: boolean; excludedWritten: string[] }

/** Record one applied bump by method classification and update the outcome counters. */
function recordBumpOutcome(outcome: ProjectApplyOutcome, method: "direct" | "constrained", c: FixCandidate, ctx: FixLoopContext, project: ProjectInfo, appliedTarget?: string): void {
  outcome.fileChanges++;
  if (method === "direct") outcome.direct++; else outcome.constrained++;
  recordApplied(ctx.allApplied, ctx.appliedKeys, {
    packageName: c.packageName,
    from: c.installedVersion,
    to: appliedTarget ?? c.targetVersion!,
    method,
    findingIds: c.findingIds,
    latest: c.latest,
    isDowngrade: c.isDowngrade,
    manifestPath: project.manifestPath,
  });
}

/** Record one applied rename (excluded renames are recorded without counters) and update the outcome. */
function recordRenameOutcome(outcome: ProjectApplyOutcome, method: "direct" | "constrained" | "excluded", c: FixCandidate, ctx: FixLoopContext, project: ProjectInfo): void {
  outcome.renamed = true;
  if (method === "direct") { outcome.fileChanges++; outcome.direct++; }
  else if (method === "constrained") { outcome.fileChanges++; outcome.constrained++; }
  recordApplied(ctx.allApplied, ctx.appliedKeys, {
    packageName: c.packageName,
    from: `${c.packageName}@${c.installedVersion}`,
    to: `${c.renameTo}@${c.targetVersion}`,
    method,
    findingIds: c.findingIds,
    isRename: true,
    manifestPath: project.manifestPath,
  });
}

/** Apply this project's share of approved bumps and record outcomes by method. */
function applyProjectBumps(project: ProjectInfo, batch: ApplyBatch, ctx: FixLoopContext, outcome: ProjectApplyOutcome, bomMap: ReadonlyMap<string, string> | null = null, protectedPins?: ReadonlySet<string>): void {
  const projectBumps = bumpsForProject(project, batch);
  const hasExcludes = isMavenLike(project) && batch.excludes.length > 0;
  if (projectBumps.length === 0 && !hasExcludes && bomMap === null) return;
  const applyResult = applyManifestBumps(project, projectBumps, batch.excludes, bomMap, protectedPins);
  for (const w of applyResult.warnings) console.log(`  [${project.label}] ${w}`);
  // Record applied bumps by method classification (direct + constrained are both written to disk)
  for (const c of batch.effectiveApproved) {
    const method = bumpApplyMethod(applyResult, c.packageName);
    if (method === "direct" || method === "constrained") recordBumpOutcome(outcome, method, c, ctx, project, applyResult.appliedTargets?.[c.packageName]);
  }
  // Exclusions: report which were actually written to this manifest; runApplyPass aggregates across projects before recording.
  for (const c of batch.effectiveExcludes) {
    if (applyResult.missed.includes(c.packageName)) outcome.excludedWritten.push(c.packageName);
  }
  if (projectBumps.length === 0 && outcome.excludedWritten.length > 0) outcome.fileChanges++;
  if (applyResult.droppedStale?.length) outcome.fileChanges++;
}

/** Apply this project's share of approved renames and record outcomes by method. */
function applyProjectRenames(project: ProjectInfo, batch: ApplyBatch, ctx: FixLoopContext, outcome: ProjectApplyOutcome): void {
  const projectRenames = renamesForProject(project, batch.renames, batch.findings, batch.packages);
  if (projectRenames.length === 0) return;
  const renameResult = applyManifestRenames(project, projectRenames);
  for (const w of renameResult.warnings) console.log(`  [${project.label}] ${w}`);
  for (const c of batch.effectiveRenames) {
    const method = appliedRenameMethod(renameResult, c);
    if (!method) continue;
    recordRenameOutcome(outcome, method, c, ctx, project);
  }
}

/** Apply this project's share of the batch and record applied entries. */
function applyProjectFixes(project: ProjectInfo, batch: ApplyBatch, ctx: FixLoopContext, bomMap: ReadonlyMap<string, string> | null = null, protectedPins?: ReadonlySet<string>): ProjectApplyOutcome {
  const outcome: ProjectApplyOutcome = { direct: 0, constrained: 0, fileChanges: 0, renamed: false, excludedWritten: [] };
  applyProjectBumps(project, batch, ctx, outcome, bomMap, protectedPins);
  applyProjectRenames(project, batch, ctx, outcome);
  return outcome;
}

/** Run the source-migration pass after renames landed (returns changed file count). */
function applySourceMigrationPass(ctx: FixLoopContext, effectiveRenames: FixCandidate[]): number {
  const sourceConfig = sourceMigrationsForAppliedRenames(renamesForSourceMigrations(effectiveRenames));
  if (!sourceConfig) return 0;
  const sourceResult = applySourceMigrations(ctx.resolvedTarget, sourceConfig);
  for (const w of sourceResult.warnings) console.log(`  [source] ${w}`);
  for (const f of sourceResult.changed) {
    console.log(`  [source] ${path.relative(ctx.resolvedTarget, f)}`);
    ctx.allSourceChanged.push(f);
    recordApplied(ctx.allApplied, ctx.appliedKeys, {
      packageName: path.relative(ctx.resolvedTarget, f),
      from: "source-migration",
      to: "migrated",
      method: "direct",
      findingIds: [],
    });
  }
  return sourceResult.changed.length;
}

interface ApplyPassOutcome { passFileChanges: number; totalDirect: number; totalConstrained: number }

/** Transactional apply for one pass: backup touched manifests, apply per project (+ source migrations), restore on failure. */
function runApplyPass(ctx: FixLoopContext, projectsToTouch: ProjectInfo[], batch: ApplyBatch, applySource: boolean, bomMaps: Map<string, Map<string, string>>, protectedByProject?: ReadonlyMap<string, ReadonlyMap<string, StaleManagedPin>>): ApplyPassOutcome {
  const outcome: ApplyPassOutcome = { passFileChanges: 0, totalDirect: 0, totalConstrained: 0 };
  const perOutcomes: ProjectApplyOutcome[] = [];
  let renamesAppliedThisPass = false;
  const applySpinner = defaultSpinnerFactory(
    maxIterations > 1 ? `Pass ${ctx.iteration}/${maxIterations} · Applying fixes...` : "Applying fixes...",
  ).start();
  try {
    runApplyTransaction({
      prepare: () => {
        for (const project of projectsToTouch) backupManifest(project);
      },
      restore: () => restoreSession(ctx.projects, ctx.allSourceChanged),
      apply: () => {
        for (const project of projectsToTouch) {
          const per = applyProjectFixes(project, batch, ctx, bomMaps.get(project.manifestPath) ?? null, protectedNames(protectedByProject, project));
          perOutcomes.push(per);
          outcome.passFileChanges += per.fileChanges;
          outcome.totalDirect += per.direct;
          outcome.totalConstrained += per.constrained;
          if (per.renamed) renamesAppliedThisPass = true;
        }
        if (applySource && renamesAppliedThisPass) {
          const changed = applySourceMigrationPass(ctx, batch.effectiveRenames);
          outcome.passFileChanges += changed;
          outcome.totalDirect += changed;
        }
        sessionJavaPaths = [...ctx.allSourceChanged];
      },
    });
  } catch (applyErr) {
    applySpinner.fail("Apply failed — restoring backups.");
    throw applyErr;
  }
  // An exclusion only counts when every touched project wrote it (Maven cannot exclude a direct dependency).
  for (const c of batch.effectiveExcludes) {
    const failedProjects = projectsToTouch.filter((_, i) => !perOutcomes[i]?.excludedWritten.includes(c.packageName));
    if (failedProjects.length === 0) {
      ctx.approvedExcludeCoords.add(c.packageName);
      recordApplied(ctx.allApplied, ctx.appliedKeys, { packageName: c.packageName, from: c.installedVersion, to: "excluded", method: "direct", findingIds: c.findingIds });
    } else {
      ctx.excludeFailedCoords.add(c.packageName);
      console.log(`  ⚠️ could not exclude ${c.packageName} in ${failedProjects.map(p => p.label).join(", ")} — likely a direct dependency, which Maven cannot exclude. Remove it from the manifest manually, or use --exclude=${c.packageName}`);
    }
  }
  applySpinner.succeed(
    outcome.passFileChanges > 0
      ? `Applied ${outcome.passFileChanges} file change(s): ${outcome.totalDirect} direct, ${outcome.totalConstrained} constrained.`
      : batch.effectiveExcludes.length > 0 && ctx.excludeFailedCoords.size > 0
        ? "No file changes — approved exclusions could not be written (see warnings)."
        : `No file changes needed (plan already satisfied).`,
  );
  return outcome;
}

/** Dry-run/CI report or interactive confirm before applying. Exits when not proceeding. */
async function reportOrConfirmApply(ctx: FixLoopContext, pass: PassPlan, plannedSourceMigrations: SourceMigrationConfig | null, applySource: boolean): Promise<void> {
  if (dryRun || (!applyFlag && !isTTY)) {
    console.log(planMarkdown(
      // Show what apply will actually execute (after unresolvable/unpublished drops), not the raw plan —
      // a raw candidate whose target is unpublished would otherwise appear as a phantom planned bump.
      { ...pass.plan, fixable: pass.effectiveApproved, renames: pass.effectiveRenames, downgrades: [] },
      { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: dryRun ? [] : ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: plannedSourceMigrations, skippedSourceMigrations: plannedSourceMigrations !== null && !applySource && !allowSourceMigrations, excludeFailed: ctx.excludeFailedCoords },
    ));
    process.exit(0);
  }
  if (!applyFlag && isTTY && ctx.iteration === 1) {
    console.log(planMarkdown(
      { ...pass.plan, fixable: pass.effectiveApproved, renames: pass.effectiveRenames, downgrades: [] },
      { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: plannedSourceMigrations, skippedSourceMigrations: plannedSourceMigrations !== null && !applySource, excludeFailed: ctx.excludeFailedCoords },
    ));
    const total = pass.effectiveApproved.length + pass.effectiveRenames.length + pass.effectiveExcludes.length;
    const proceed = await ask(`Apply ${total} change(s)? [y/N] `);
    if (!proceed) process.exit(1);
  }
}

/** Final verification scan across all project ecosystems. */
async function runFinalScan(ctx: FixLoopContext): Promise<{ findings: Finding[]; packages: PackageRef[]; unresolved: string[] }> {
  const findings: Finding[] = [];
  const packages: PackageRef[] = [];
  const advisories: AdvisoryEntry[] = [];
  const unresolved: string[] = [];
  for (const eco of ctx.ecoFilters) {
    const result = await runAutoBumperScan(ctx.resolvedTarget, {
      ecosystemFilter: eco,
      quietBanner: true,
      ora: defaultSpinnerFactory,
      spinnerPrefix: "Final check",
      gradleConfigurations: GRADLE_ALL_CONFIGURATIONS,
      offline: offlineFlag,
      excludePackages: [...excludeArgs, ...ctx.approvedExcludeCoords],
    });
    findings.push(...result.findings);
    packages.push(...result.packages);
    advisories.push(...result.advisories);
    for (const u of result.unresolved ?? []) {
      if (!unresolved.includes(u)) unresolved.push(u);
    }
    if (result.incomplete) ctx.incompleteScan = true;
  }
  if (ctx.lockUnsynced) {
    console.log("  Lockfile was not updated. Final check uses the lockfile, not the manifest.");
    return { findings, packages, unresolved };
  }
  const overlay = overlayScanResult(packages, findings, advisories, ctx.resolvedTarget, [...ctx.approvedExcludeCoords]);
  if (overlay.overlaid.length > 0) console.log(`  ${MANIFEST_OVERLAY_WARNING}`);
  return { findings: overlay.findings, packages: overlay.packages, unresolved };
}

/** Crate names applied in dir. Renames use the new name (`to` is `name@version`). */
function cargoPackageNames(ctx: FixLoopContext, dir: string): string[] {
  const resolved = path.resolve(dir);
  const names: string[] = [];
  for (const bump of ctx.allApplied) {
    if (!bump.manifestPath) continue;
    if (path.resolve(path.dirname(bump.manifestPath)) !== resolved) continue;
    if (!bump.manifestPath.replaceAll("\\", "/").endsWith("Cargo.toml")) continue;
    const at = bump.to.lastIndexOf("@");
    const name = bump.isRename && at > 0 ? bump.to.slice(0, at) : bump.packageName;
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}

/** After a manifest edit, rewrite npm/Cargo/Poetry lockfiles so the next scan sees the new pins. */
function refreshLocksAfterApply(ctx: FixLoopContext, dirs: string[]): void {
  const seen = new Set<string>();
  for (const dir of dirs) {
    const resolved = path.resolve(dir);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    const cargoPackages = cargoPackageNames(ctx, resolved);
    const planned = lockRefreshCommands(resolved, { cargoPackages });
    if (planned.length === 0) continue;
    if (offlineFlag) {
      ctx.lockUnsynced = true;
      console.log(`  Lockfile left unchanged (--offline) in ${resolved}. It may still pin the vulnerable version.`);
      continue;
    }
    console.log(`  Updating lockfile (${planned.map(c => c.label).join(", ")})...`);
    for (const result of refreshProjectLocks(resolved, 300_000, { cargoPackages })) {
      if (result.warn) console.log(`  ${result.warn}`);
      if (result.ok) console.log(`  Lockfile updated (${result.label}).`);
      else {
        ctx.lockUnsynced = true;
        console.log(`  Lockfile update failed (${result.label}): ${result.detail}`);
      }
    }
  }
}

/** Compile-check command for a Java project; null when no build tool is available. */
function javaCompileCommand(project: ProjectInfo): { bin: string; args: string[]; label: string } | null {
  const dir = path.dirname(project.manifestPath);
  if (project.kind === "gradle") {
    const gradlew = detectGradlew(dir);
    return gradlew ? { bin: gradlew, args: ["compileJava", "compileTestJava", "--console=plain", "-q"], label: "gradlew compileJava compileTestJava" } : null;
  }
  const mvn = detectMaven(dir);
  return mvn ? { bin: mvn.executable, args: ["-q", "-DskipTests", "test-compile"], label: "mvn -q -DskipTests test-compile" } : null;
}

/** Run a compile check synchronously; returns the tail of the output on failure. */
function runCompileCheck(command: { bin: string; args: string[] }, cwd: string): { ok: boolean; detail: string } {
  const base = { encoding: "utf-8" as const, timeout: 900_000, cwd, maxBuffer: 10 * 1024 * 1024, windowsHide: true, shell: false as const };
  let result;
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(command.bin)) {
    const comspec = process.env.ComSpec || "cmd.exe";
    result = childProcess.spawnSync(comspec, windowsBatchArgs(command.bin, command.args), { ...base, windowsVerbatimArguments: true });
  } else {
    result = childProcess.spawnSync(command.bin, command.args, base);
  }
  if (result.status === 0 && !result.error) return { ok: true, detail: "" };
  const text = `${result.stderr || ""}\n${result.stdout || ""}`.trim();
  const tail = text.split(/\r?\n/).filter(Boolean).slice(-3).join(" ");
  return { ok: false, detail: (tail || result.error?.message || `exit ${result.status}`).slice(0, 400) };
}

/**
 * Compile-check projects whose applied batch contains downgrades. A downgrade moves to an older
 * release whose API may not satisfy the project's code; when the build fails, that project's
 * downgrade bumps are rolled back one by one (original versions kept) and the target is marked
 * unresolvable for the rest of the session so the loop does not retry it.
 */
function verifyDowngradeBuilds(ctx: FixLoopContext, projectsToTouch: ProjectInfo[]): void {
  for (const project of projectsToTouch) {
    if (!isMavenLike(project)) continue;
    const downgrades = ctx.allApplied.filter(r => r.manifestPath === project.manifestPath && r.isDowngrade);
    if (downgrades.length === 0) continue;
    if (offlineFlag) {
      console.log(`  ! ${project.label}: skipping compile check for ${downgrades.length} downgrade(s) — --offline`);
      continue;
    }
    const command = javaCompileCommand(project);
    if (!command) {
      console.log(`  ! ${project.label}: no build tool found — skipping compile check for ${downgrades.length} downgrade(s)`);
      continue;
    }
    console.log(`  Compiling ${project.label} after downgrade (${command.label})...`);
    const result = runCompileCheck(command, path.dirname(project.manifestPath));
    if (result.ok) {
      console.log(`  ! ${project.label}: downgrade(s) compile-checked only — runtime behavior NOT verified; run the project's test suite`);
      continue;
    }
    console.log(`  ! ${project.label}: build failed after downgrade: ${result.detail}`);
    for (const r of downgrades) {
      const removePin = project.kind === "gradle" ? removeGradleManagedPin : removeMavenManagedPin;
      removePin(project.manifestPath, r.packageName);
      if (r.method === "direct") restoreDirectBump(project, r);
      const idx = ctx.allApplied.indexOf(r);
      if (idx !== -1) ctx.allApplied.splice(idx, 1);
      ctx.appliedKeys.delete(`${r.packageName}|${r.from}|${r.to}`);
      ctx.sessionUnresolvable.add(`${r.packageName.toLowerCase()}@${r.to.toLowerCase()}`);
      ctx.allRolledBackDowngrades.push(r);
      console.log(`  ~ rolled back ${r.packageName}: build failed after downgrade to ${r.to} (kept ${r.from})`);
    }
  }
}

/** Final report after the fix loop; always exits. */
function reportFinal(ctx: FixLoopContext, finalFindings: Finding[]): never {
  const reportApplied = dedupeApplied(ctx.allApplied);
  // Successfully excluded packages are reported in the Applied section — do not re-list them as unfixable.
  const unfixableShown = ctx.lastUnfixable.filter(u => !ctx.approvedExcludeCoords.has(u.packageName));
  console.log(planMarkdown(
    { fixable: [], unfixable: unfixableShown, renames: [], downgrades: [] },
    { applied: reportApplied, unfixableRemaining: unfixableShown, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: finalFindings.map(f => ({ packageName: f.packageName, installedVersion: f.installedVersion, id: f.id, aliases: f.aliases })), skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, familyMigrations: ctx.lastFamilyMigrations, sourceMigrations: null, skippedSourceMigrations: false, skippedUnresolvable: ctx.allSkippedUnresolvable, excludeFailed: ctx.excludeFailedCoords },
  ));
  // The run reached a terminal state — crash recovery is over, so clean up backups on every
  // exit path; a leftover .bak would otherwise look like an unprocessed restore.
  for (const p of ctx.projects) discardManifestBackup(p);
  discardSourceMigrationBackups(ctx.allSourceChanged);
  if (ctx.lockUnsynced && reportApplied.length > 0) {
    console.error("Lockfile was not updated after apply. The lock may still pin the vulnerable version.");
    process.exit(1);
  }
  if (finalFindings.length === 0 && ctx.allSkippedUnresolvable.length === 0 && ctx.allRolledBackDowngrades.length === 0) {
    if (ctx.incompleteScan) {
      console.error("Scan incomplete: dependency tree or advisory data was not fully loaded. Not reporting a clean result.");
      process.exit(2);
    }
    console.log(reportApplied.length > 0 ? "All vulnerabilities fixed." : "No vulnerabilities found.");
    process.exit(0);
  }
  if (finalFindings.length > 0) console.log(`Remaining vulnerabilities: ${finalFindings.length}`);
  if (ctx.allSkippedUnresolvable.length > 0) console.log(`Rolled back fixes: ${ctx.allSkippedUnresolvable.length} — target version not resolvable from project repositories.`);
  if (ctx.allRolledBackDowngrades.length > 0) console.log(`Rolled back downgrades: ${ctx.allRolledBackDowngrades.length} — build failed after downgrade; original versions kept.`);
  if (reportApplied.length > 0) console.log("Bumps were applied. Re-run scan to verify, or use --exclude=group:artifact for unfixable OSV noise.");
  process.exit((finalFindings.length > 0 || ctx.allSkippedUnresolvable.length > 0 || ctx.allRolledBackDowngrades.length > 0) && strictExit ? 1 : 0);
}

async function main() {
  const resolvedTarget = normalizeCliPath(targetPath);
  const projects = findProjects(resolvedTarget, ecosystemFilter);
  sessionProjects = projects;

  if (projects.length === 0) failNoProjects(resolvedTarget);

  const labels = projects.map(p => p.label);
  console.log(`Found ${labels.join(", ")} project${projects.length > 1 ? "s" : ""} in ${resolvedTarget}`);
  // The cache (.auto-bumper) resolves from process.cwd(); anchor it to the target project so results do not depend on where the CLI was invoked.
  process.chdir(resolvedTarget);

  const ctx: FixLoopContext = {
    resolvedTarget,
    projects,
    labels,
    ecoFilters: new Set(projects.map(p => scanEcosystemFilterForKind(p.kind))),
    allApplied: [],
    appliedKeys: new Set<string>(),
    allSourceChanged: [],
    allSkippedMajors: [],
    allSkippedRenames: [],
    allSkippedUnresolvable: [],
    sessionUnresolvable: new Set<string>(),
    approvedExcludeCoords: new Set<string>(),
    excludeFailedCoords: new Set<string>(),
    lastUnfixable: [],
    lastFamilyMigrations: [],
    allRolledBackDowngrades: [],
    lastHealthWarnings: [],
    iteration: 0,
    prevFindingSig: null,
    prevPlanSig: null,
    lastAppliedCount: 0,
    findingCountHistory: [],
    lockUnsynced: false,
    incompleteScan: false,
  };

  // Prune stale backups left by earlier runs: if the manifest has since diverged from its .bak,
  // that snapshot is no longer a valid pre-state and could restore stale content on failure.
  // An identical .bak (e.g. an interrupted run) is still valid and is kept. Never touch files in dry-run.
  if (!dryRun && (applyFlag || isTTY)) {
    for (const p of projects) discardStaleBackup(p.manifestPath);
  }
  while (ctx.iteration < maxIterations) {
    ctx.iteration++;
    const scan = await runScanPass(ctx);
    await rollBackUnresolvable(selectUnresolvableRollbacks(ctx.allApplied, scan.unresolved, scan.packages), projects, ctx.allApplied, ctx.appliedKeys, ctx.allSkippedUnresolvable, ctx.sessionUnresolvable);
    const latestCandidates = await buildLatestForProjects(ctx, scan.packages);
    const bomMaps = await loadBomManagedMaps(projects);
    const protectedByProject = computeProtectedPinsByProject(projects, bomMaps, scan.advisories);
    if (outputFormat !== "json") {
      for (const pins of protectedByProject.values()) {
        for (const [pkg, st] of pins) console.log(`  ~ keeping pin ${pkg}@${st.version} — BOM-managed ${st.bomVersion} is still vulnerable; dropping it would reintroduce the finding`);
      }
    }
    const cleanedStalePins = await cleanupStaleBomPins(projects, bomMaps, protectedByProject);

    // A pin dropped this iteration can expose a finding the pre-cleanup scan did not see — rescan first.
    if (scan.findings.length === 0 && !cleanedStalePins && (!latestFlag || latestCandidates.length === 0)) reportCleanExit(ctx);

    const currentSig = findingSignature(scan.findings);
    ctx.findingCountHistory.push(scan.findings.length);
    if (loopStopped(ctx, scan.findings.length, currentSig, true)) break;

    const pass = await buildPassPlan(ctx, scan, latestCandidates);
    const nothingToApply = pass.effectiveApproved.length === 0 && pass.effectiveRenames.length === 0 && pass.effectiveExcludes.length === 0;
    if (nothingToApply) {
      // Pin cleanup rewrote a manifest this iteration — the scan predates it, so rescan once for a
      // report that reflects the new resolution instead of exiting on stale findings.
      if (cleanedStalePins) continue;
      if (handleNothingApproved(ctx, pass, scan.findings.length)) break;
    }

    const currentPlanSig = planSignature(pass.effectiveApproved, pass.effectiveRenames);
    if (loopStopped(ctx, scan.findings.length, currentSig, false, currentPlanSig, ctx.prevPlanSig)) break;

    const plannedSourceMigrations = plannedSourceMigrationsFor(pass);
    const batch = buildApplyBatch(pass, scan.findings, scan.packages);
    const { approved: applySource } = await filterBySourceGate(pass.effectiveRenames, pass.effectiveRenames.length > 0);
    await reportOrConfirmApply(ctx, pass, plannedSourceMigrations, applySource);

    const projectsToTouch = projects.filter(project => bumpsForProject(project, batch).length > 0 || renamesForProject(project, batch.renames, batch.findings, batch.packages).length > 0 || (pass.effectiveExcludes.length > 0 && isMavenLike(project)) || bomPinCleanupNeeded(project, bomMaps, protectedByProject));
    const applied = runApplyPass(ctx, projectsToTouch, batch, applySource, bomMaps, protectedByProject);
    ctx.lastAppliedCount = applied.passFileChanges;
    if (applied.passFileChanges > 0) {
      refreshLocksAfterApply(ctx, projectsToTouch.map(p => path.dirname(p.manifestPath)));
    }
    verifyDowngradeBuilds(ctx, projectsToTouch);
    ctx.prevPlanSig = currentPlanSig;
    ctx.prevFindingSig = currentSig;
  }

  let finalScan = await runFinalScan(ctx);
  const finalRollbacks = await rollBackUnresolvable(selectUnresolvableRollbacks(ctx.allApplied, finalScan.unresolved, finalScan.packages), projects, ctx.allApplied, ctx.appliedKeys, ctx.allSkippedUnresolvable, ctx.sessionUnresolvable);
  if (finalRollbacks > 0) finalScan = await runFinalScan(ctx);

  reportFinal(ctx, finalScan.findings);
}

if (import.meta.main) {
  try {
    await main();
  } catch (err) {
    if (sessionProjects.length > 0) {
      console.error("Restoring backups after failure...");
      restoreSession(sessionProjects, sessionJavaPaths);
    }
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Fix failed: ${msg}`);
    process.exit(2);
  }
}
