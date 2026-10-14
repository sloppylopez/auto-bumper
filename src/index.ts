export {
  runAutoBumperScan,
  normalizeCliPath,
  pathHint,
  repairMangledCliPath,
} from "./scan.ts";
export type { ScanResult, ScanOptions } from "./scan.ts";
export type { AdvisoryEntry } from "./lib/types.ts";

export { parseLockfile, parseBuildGradle, parsePomXml, ECOSYSTEM_OSV_NAME } from "./lib/parse-lockfile.ts";
export type { ParseResult } from "./lib/parse-lockfile.ts";

export { matchVulnerabilities, compareMavenVersion } from "./lib/matcher.ts";

export { loadRepoAdvisories, getWatchedRepos, DEFAULT_WATCHED_REPOS } from "./lib/github-repo-advisories.ts";

export { buildFixPlan } from "./lib/fixer.ts";
export type { FixPlan, FixCandidate } from "./lib/fixer.ts";

export { applyBumps, backupBuildGradle, restoreBuildGradle, discardBackup } from "./lib/gradle-editor.ts";
export type { BumpRequest, ExcludeRequest, ApplyResult } from "./lib/gradle-editor.ts";

export {
  applyBumps as applyMavenBumps,
  backupPomXml,
  restorePomXml,
  discardBackup as discardMavenBackup,
} from "./lib/pom-editor.ts";

export {
  applyBumps as applyNpmBumps,
  backupPackageJson,
  restorePackageJson,
  discardBackup as discardNpmBackup,
  findPackageJson,
} from "./lib/npm-editor.ts";

export {
  applyBumps as applyCargoBumps,
  backupCargoToml,
  restoreCargoToml,
  discardBackup as discardCargoBackup,
} from "./lib/cargo-editor.ts";

export {
  applyToRequirementsTxt,
  applyToPyprojectToml,
  backupRequirementsTxt,
  restoreRequirementsTxt,
  discardRequirementsBackup,
  backupPyprojectToml,
  restorePyprojectToml,
  discardPyprojectBackup,
} from "./lib/python-editor.ts";

export { debug } from "./lib/debug.ts";

export { reportMarkdown, reportJson, reportSummary } from "./lib/reporter.ts";

export type { Finding, PackageRef } from "./lib/types.ts";
export { sortBySeverity, SeverityOrder } from "./lib/types.ts";
export type { BumpRequest as NpmBumpRequest, ApplyResult as NpmApplyResult } from "./lib/npm-editor.ts";
export type { BumpRequest as CargoBumpRequest, ApplyResult as CargoApplyResult } from "./lib/cargo-editor.ts";
export type { BumpRequest as PyBumpRequest, ApplyResult as PyApplyResult } from "./lib/python-editor.ts";
