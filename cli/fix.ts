#!/usr/bin/env bun
/**
 * Auto-Bumper Fix — Polyglot auto-remediation for Java, npm, Rust, Python.
 *
 * Usage:
 *   fix [path] [--dry-run] [--apply] [--allow-major] [--allow-renames] [--allow-source-migrations] [--latest] [--offline] [options]
 *   bun cli/fix.ts [path] [options]   (local dev)
 */
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { defaultSpinnerFactory } from "../src/lib/spinner.ts";
import { runAutoBumperScan, normalizeCliPath, pathHint } from "../src/scan.ts";
import { GRADLE_ALL_CONFIGURATIONS, parseBuildGradleDirect, parsePomXmlDirect } from "../src/lib/parse-lockfile.ts";
import { buildFixPlan, majorOf } from "../src/lib/fixer.ts";
import type { FixCandidate, FixPlan } from "../src/lib/fixer.ts";
import { bumpApplyMethod, normalizeBumpApplyResult, type BumpApplyResult } from "../src/lib/apply-method.ts";
import { selectUnresolvableRollbacks } from "../src/lib/unresolvable.ts";
import { findLatestAvailableVersion, findNextAvailableVersion, versionPublishedInRepos } from "../src/lib/repo-metadata.ts";
import { compareMavenVersion } from "../src/lib/matcher.ts";
import {
  applyBumps as applyGradleBumps,
  applyRenames as applyGradleRenames,
  backupBuildGradle,
  discardBackup as discardGradleBackup,
  removeManagedPin as removeGradleManagedPin,
  restoreBuildGradle,
  restoreDeclaredVersion as restoreGradleDeclaredVersion,
} from "../src/lib/gradle-editor.ts";
import type { RenameRequest } from "../src/lib/gradle-editor.ts";
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
import { applyPolicyForRenames, expandRenameBundle, sourceMigrationsForAppliedRenames } from "../src/lib/maven-renames.ts";
import { scanEcosystemFilterForKind } from "../src/lib/ecosystem-filter.ts";
import type { RenameApplyPolicy, SourceMigrationConfig } from "../src/lib/maven-renames.ts";
import {
  applySourceMigrations,
  describeSourceMigrations,
  discardSourceMigrationBackups,
  restoreSourceMigrationBackups,
} from "../src/lib/source-migrations.ts";
import { runApplyTransaction } from "../src/lib/backup.ts";
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
const allowRenames = args.includes("--allow-renames");
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
  : 5;
const excludeArgs = args.filter(a => a.startsWith("--exclude=")).map(a => a.split("=")[1]!);
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

  // Python
  const reqTxt = path.join(resolved, "requirements.txt");
  const pyproject = path.join(resolved, "pyproject.toml");
  if ((fs.existsSync(reqTxt) || fs.existsSync(pyproject)) && (!filter || filter === "pypi")) {
    const manifest = fs.existsSync(pyproject) ? pyproject : reqTxt;
    projects.push({ kind: "pypi", manifestPath: manifest, label: "Python" });
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
  labels: string[];
  skippedMajors: FixCandidate[];
  remainingFindings?: Array<{ packageName: string; installedVersion: string; id: string; aliases: string[] }>;
  skippedRenames?: FixCandidate[];
  healthWarnings?: string[];
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
    const ref = a.latest ? "(latest)" : `[${a.findingIds.join(", ")}]`;
    lines.push(`- ${a.packageName}: ${a.from} -> ${a.to} (${a.method}) ${ref}`);
  }
  lines.push("");
}

function pushPlannedBumps(lines: string[], fixable: FixCandidate[]): void {
  if (fixable.length === 0) return;
  lines.push(`## Planned bumps (${fixable.length})`, "", "| Package | Current | Target | Major | Advisories |", "|---------|---------|--------|-------|------------|");
  for (const c of fixable) {
    lines.push(`| ${c.packageName} | ${c.installedVersion} | ${c.targetVersion} | ${c.isMajor ? "yes" : "no"} | ${c.findingIds.length > 0 ? c.findingIds.slice(0, 2).join(", ") : "—"} |`);
  }
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
  lines.push(`## Skipped major bumps (${skippedMajors.length})`, "");
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

function pushUnfixable(lines: string[], unfixable: FixCandidate[], unfixableRemaining: FixCandidate[]): void {
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
    lines.push(`- ${u.packageName}@${u.installedVersion} — no fixed version in OSV (consider --exclude=${u.packageName})`);
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
  pushApplied(lines, opts.applied);
  pushPlannedBumps(lines, plan.fixable);
  pushPlannedRenames(lines, plan.renames);
  pushSourceMigrations(lines, opts.sourceMigrations ?? null, opts.skippedSourceMigrations ?? false);
  pushSkippedRenames(lines, opts.skippedRenames ?? []);
  pushSkippedMajors(lines, opts.skippedMajors);
  pushSkippedUnresolvable(lines, opts.skippedUnresolvable ?? []);
  pushUnfixable(lines, plan.unfixable, opts.unfixableRemaining);
  pushRemainingFindings(lines, opts.remainingFindings ?? []);
  return lines.join("\n");
}

async function filterByMajorGate(candidates: FixCandidate[]) {
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
        `Major bump ${c.packageName}: ${c.installedVersion} -> ${c.targetVersion}? [y/N] `,
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

function applyManifestBumps(project: ProjectInfo, bumps: BumpRequest[], excludes: { packageName: string }[]): BumpApplyResult {
  if (project.kind === "maven") return normalizeBumpApplyResult(applyMavenBumps(project.manifestPath, bumps, excludes));
  if (project.kind === "gradle") return normalizeBumpApplyResult(applyGradleBumps(project.manifestPath, bumps, excludes));
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
): RenameRequest[] {
  const eco = projectEcosystemForKind(project.kind);
  return renames.filter(r => {
    const findingEco = findings.find(f => f.packageName === r.fromPackage)?.ecosystem;
    return findingEco === eco;
  });
}

function mapBumps(approved: FixCandidate[]): BumpRequest[] {
  return approved.map(c => ({
    packageName: c.packageName,
    targetVersion: c.targetVersion!,
    because: c.findingIds,
    ecosystem: c.ecosystem,
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
  sessionUnresolvable: Set<string>;
  lastUnfixable: FixCandidate[];
  lastHealthWarnings: string[];
  iteration: number;
  prevFindingSig: string | null;
  prevPlanSig: string | null;
  lastAppliedCount: number;
  findingCountHistory: number[];
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
      excludePackages: excludeArgs,
    });
    result.findings.push(...scan.findings);
    result.warnings.push(...scan.warnings);
    result.advisories.push(...scan.advisories);
    result.packages.push(...scan.packages);
    for (const u of scan.unresolved ?? []) {
      if (!result.unresolved.includes(u)) result.unresolved.push(u);
    }
  }
  // Remember every coordinate the build could not resolve — never re-apply a fix targeting it.
  for (const u of result.unresolved) ctx.sessionUnresolvable.add(u);

  if (ctx.iteration > 1) {
    const overlay = overlayManifestDirectDeps(result.packages, ctx.resolvedTarget);
    result.packages = overlay.packages;
    if (overlay.overlaid.length > 0) console.log(`  ${MANIFEST_OVERLAY_WARNING}`);
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
  if (outputFormat === "json") {
    console.log(JSON.stringify({ status: "clean", applied: ctx.allApplied, skippedMajors: ctx.allSkippedMajors, skippedUnresolvable: ctx.allSkippedUnresolvable }, null, 2));
  } else if (ctx.allSkippedUnresolvable.length > 0) {
    console.log(planMarkdown({ fixable: [], unfixable: [], renames: [] }, { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, sourceMigrations: null, skippedSourceMigrations: false, skippedUnresolvable: ctx.allSkippedUnresolvable }));
    console.log(`Remaining issues: ${ctx.allSkippedUnresolvable.length} fix(es) rolled back — target version not resolvable from project repositories.`);
  } else if (ctx.allApplied.length > 0) {
    console.log(planMarkdown({ fixable: [], unfixable: [], renames: [] }, { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings }));
    console.log("All vulnerabilities fixed.");
  } else {
    console.log("No vulnerabilities found.");
  }
  for (const p of ctx.projects) discardManifestBackup(p);
  discardSourceMigrationBackups(ctx.allSourceChanged);
  process.exit(ctx.allSkippedUnresolvable.length > 0 && strictExit ? 1 : 0);
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
  policy: RenameApplyPolicy;
}

async function buildPassPlan(ctx: FixLoopContext, scan: ScanPassResult, latestCandidates: FixCandidate[]): Promise<PassPlan> {
  const plan = buildFixPlan(scan.findings, dedupeAdvisories(scan.advisories));
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
  const policy = applyPolicyForRenames(effectiveRenames.map(r => ({ fromPackage: r.packageName, toPackage: r.renameTo ?? "" })));
  return { plan, approved, skippedMajors: skipped, approvedRenames, skippedRenames, effectiveApproved, effectiveRenames, policy };
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
  const showPlan = dryRun && (pass.plan.fixable.length > 0 || pass.plan.renames.length > 0);
  if (showPlan) {
    console.log(planMarkdown(pass.plan, { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, sourceMigrations: sourceMigrationsForAppliedRenames(renamesForSourceMigrations(pass.plan.renames)) }));
    process.exit(0);
  }
  console.log(planMarkdown({ ...pass.plan, fixable: [] }, { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, sourceMigrations: null, skippedSourceMigrations: false, skippedUnresolvable: ctx.allSkippedUnresolvable }));
  console.log("Nothing to apply.");
  if (pass.skippedMajors.length > 0) console.log(`  - ${pass.skippedMajors.length} major bump(s) skipped — approve at prompt, or use --allow-major`);
  if (pass.skippedRenames.length > 0) console.log(`  - ${pass.skippedRenames.length} rename(s) skipped — approve at prompt, or use --allow-renames`);
  if (pass.plan.unfixable.length > 0) console.log(`  - ${pass.plan.unfixable.length} package(s) have no OSV fix version — use --exclude=group:artifact to ignore`);
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
  excludes: Array<{ packageName: string }>;
  findings: Finding[];
}

/** Build the apply batch for one pass (policy pins, rename requests, exclude coordinates). */
function buildApplyBatch(pass: PassPlan, findings: Finding[]): ApplyBatch {
  let bumps = mapBumps(pass.effectiveApproved).filter(b => !pass.policy.rejectPins.has(b.packageName));
  for (const p of pass.policy.extraPins) {
    if (!bumps.some(b => b.packageName === p.packageName)) {
      bumps.push({ packageName: p.packageName, targetVersion: p.version, because: ["migration-policy"] });
    }
  }
  const renames = mapRenames(pass.effectiveRenames);
  const excludes = [
    ...excludeArgs.map(coord => ({ packageName: coord })),
    ...(pass.policy.excludeOldCoordinates ? pass.effectiveRenames.map(r => ({ packageName: r.packageName })) : []),
  ];
  return { bumps, renames, effectiveApproved: pass.effectiveApproved, effectiveRenames: pass.effectiveRenames, excludes, findings };
}

/** Bumps belonging to one project (maven/gradle share the maven ecosystem). */
function bumpsForProject(project: ProjectInfo, batch: ApplyBatch): BumpRequest[] {
  return batch.bumps.filter(b => {
    const pkgEco = b.ecosystem ?? batch.findings.find(f => f.packageName === b.packageName)?.ecosystem;
    if (project.kind === "maven" || project.kind === "gradle") return pkgEco === "maven";
    return pkgEco === project.kind;
  });
}

interface ProjectApplyOutcome { direct: number; constrained: number; fileChanges: number; renamed: boolean }

/** Record one applied bump by method classification and update the outcome counters. */
function recordBumpOutcome(outcome: ProjectApplyOutcome, method: "direct" | "constrained", c: FixCandidate, ctx: FixLoopContext, project: ProjectInfo): void {
  outcome.fileChanges++;
  if (method === "direct") outcome.direct++; else outcome.constrained++;
  recordApplied(ctx.allApplied, ctx.appliedKeys, {
    packageName: c.packageName,
    from: c.installedVersion,
    to: c.targetVersion!,
    method,
    findingIds: c.findingIds,
    latest: c.latest,
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
function applyProjectBumps(project: ProjectInfo, batch: ApplyBatch, ctx: FixLoopContext, outcome: ProjectApplyOutcome): void {
  const projectBumps = bumpsForProject(project, batch);
  if (projectBumps.length === 0) return;
  const applyResult = applyManifestBumps(project, projectBumps, batch.excludes);
  for (const w of applyResult.warnings) console.log(`  [${project.label}] ${w}`);
  // Record applied bumps by method classification (direct + constrained are both written to disk)
  for (const c of batch.effectiveApproved) {
    const method = bumpApplyMethod(applyResult, c.packageName);
    if (method === "direct" || method === "constrained") recordBumpOutcome(outcome, method, c, ctx, project);
  }
}

/** Apply this project's share of approved renames and record outcomes by method. */
function applyProjectRenames(project: ProjectInfo, batch: ApplyBatch, ctx: FixLoopContext, outcome: ProjectApplyOutcome): void {
  const projectRenames = renamesForProject(project, batch.renames, batch.findings);
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
function applyProjectFixes(project: ProjectInfo, batch: ApplyBatch, ctx: FixLoopContext): ProjectApplyOutcome {
  const outcome: ProjectApplyOutcome = { direct: 0, constrained: 0, fileChanges: 0, renamed: false };
  applyProjectBumps(project, batch, ctx, outcome);
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
function runApplyPass(ctx: FixLoopContext, projectsToTouch: ProjectInfo[], batch: ApplyBatch, applySource: boolean): ApplyPassOutcome {
  const outcome: ApplyPassOutcome = { passFileChanges: 0, totalDirect: 0, totalConstrained: 0 };
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
          const per = applyProjectFixes(project, batch, ctx);
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
  applySpinner.succeed(
    outcome.passFileChanges > 0
      ? `Applied ${outcome.passFileChanges} file change(s): ${outcome.totalDirect} direct, ${outcome.totalConstrained} constrained.`
      : `No file changes needed (plan already satisfied).`,
  );
  return outcome;
}

/** Dry-run/CI report or interactive confirm before applying. Exits when not proceeding. */
async function reportOrConfirmApply(ctx: FixLoopContext, pass: PassPlan, plannedSourceMigrations: SourceMigrationConfig | null, applySource: boolean): Promise<void> {
  if (dryRun || (!applyFlag && !isTTY)) {
    console.log(planMarkdown(
      { ...pass.plan, fixable: dryRun ? pass.plan.fixable : pass.approved, renames: dryRun ? pass.plan.renames : pass.approvedRenames },
      { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: dryRun ? [] : ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, sourceMigrations: plannedSourceMigrations, skippedSourceMigrations: plannedSourceMigrations !== null && !applySource && !allowSourceMigrations },
    ));
    process.exit(0);
  }
  if (!applyFlag && isTTY && ctx.iteration === 1) {
    console.log(planMarkdown(
      { ...pass.plan, fixable: pass.approved, renames: pass.approvedRenames },
      { applied: ctx.allApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: [], skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, sourceMigrations: plannedSourceMigrations, skippedSourceMigrations: plannedSourceMigrations !== null && !applySource },
    ));
    const total = pass.approved.length + pass.approvedRenames.length;
    const proceed = await ask(`Apply ${total} change(s)? [y/N] `);
    if (!proceed) process.exit(1);
  }
}

/** Final verification scan across all project ecosystems. */
async function runFinalScan(ctx: FixLoopContext): Promise<{ findings: Finding[]; packages: PackageRef[]; unresolved: string[] }> {
  const findings: Finding[] = [];
  const packages: PackageRef[] = [];
  const unresolved: string[] = [];
  for (const eco of ctx.ecoFilters) {
    const result = await runAutoBumperScan(ctx.resolvedTarget, {
      ecosystemFilter: eco,
      quietBanner: true,
      ora: defaultSpinnerFactory,
      spinnerPrefix: "Final check",
      gradleConfigurations: GRADLE_ALL_CONFIGURATIONS,
      offline: offlineFlag,
      excludePackages: excludeArgs,
    });
    findings.push(...result.findings);
    packages.push(...result.packages);
    for (const u of result.unresolved ?? []) {
      if (!unresolved.includes(u)) unresolved.push(u);
    }
  }
  return { findings, packages, unresolved };
}

/** Final report after the fix loop; always exits. */
function reportFinal(ctx: FixLoopContext, finalFindings: Finding[]): never {
  const reportApplied = dedupeApplied(ctx.allApplied);
  console.log(planMarkdown(
    { fixable: [], unfixable: ctx.lastUnfixable, renames: [] },
    { applied: reportApplied, unfixableRemaining: ctx.lastUnfixable, labels: ctx.labels, skippedMajors: ctx.allSkippedMajors, remainingFindings: finalFindings.map(f => ({ packageName: f.packageName, installedVersion: f.installedVersion, id: f.id, aliases: f.aliases })), skippedRenames: ctx.allSkippedRenames, healthWarnings: ctx.lastHealthWarnings, sourceMigrations: null, skippedSourceMigrations: false, skippedUnresolvable: ctx.allSkippedUnresolvable },
  ));
  if (finalFindings.length === 0 && ctx.allSkippedUnresolvable.length === 0) {
    console.log(reportApplied.length > 0 ? "All vulnerabilities fixed." : "No vulnerabilities found.");
    for (const p of ctx.projects) discardManifestBackup(p);
    discardSourceMigrationBackups(ctx.allSourceChanged);
    process.exit(0);
  }
  if (finalFindings.length > 0) console.log(`Remaining vulnerabilities: ${finalFindings.length}`);
  if (ctx.allSkippedUnresolvable.length > 0) console.log(`Rolled back fixes: ${ctx.allSkippedUnresolvable.length} — target version not resolvable from project repositories.`);
  if (reportApplied.length > 0) console.log("Bumps were applied. Re-run scan to verify, or use --exclude=group:artifact for unfixable OSV noise.");
  process.exit((finalFindings.length > 0 || ctx.allSkippedUnresolvable.length > 0) && strictExit ? 1 : 0);
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
    lastUnfixable: [],
    lastHealthWarnings: [],
    iteration: 0,
    prevFindingSig: null,
    prevPlanSig: null,
    lastAppliedCount: 0,
    findingCountHistory: [],
  };

  while (ctx.iteration < maxIterations) {
    ctx.iteration++;
    const scan = await runScanPass(ctx);
    await rollBackUnresolvable(selectUnresolvableRollbacks(ctx.allApplied, scan.unresolved, scan.packages), projects, ctx.allApplied, ctx.appliedKeys, ctx.allSkippedUnresolvable, ctx.sessionUnresolvable);
    const latestCandidates = await buildLatestForProjects(ctx, scan.packages);

    if (scan.findings.length === 0 && (!latestFlag || latestCandidates.length === 0)) reportCleanExit(ctx);

    const currentSig = findingSignature(scan.findings);
    ctx.findingCountHistory.push(scan.findings.length);
    if (loopStopped(ctx, scan.findings.length, currentSig, true)) break;

    const pass = await buildPassPlan(ctx, scan, latestCandidates);
    if (pass.effectiveApproved.length === 0 && pass.effectiveRenames.length === 0 && handleNothingApproved(ctx, pass, scan.findings.length)) break;

    const currentPlanSig = planSignature(pass.effectiveApproved, pass.effectiveRenames);
    if (loopStopped(ctx, scan.findings.length, currentSig, false, currentPlanSig, ctx.prevPlanSig)) break;

    const plannedSourceMigrations = plannedSourceMigrationsFor(pass);
    const batch = buildApplyBatch(pass, scan.findings);
    const { approved: applySource } = await filterBySourceGate(pass.effectiveRenames, pass.effectiveRenames.length > 0);
    await reportOrConfirmApply(ctx, pass, plannedSourceMigrations, applySource);

    const projectsToTouch = projects.filter(project => bumpsForProject(project, batch).length > 0 || renamesForProject(project, batch.renames, batch.findings).length > 0);
    const applied = runApplyPass(ctx, projectsToTouch, batch, applySource);
    ctx.lastAppliedCount = applied.passFileChanges;
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
