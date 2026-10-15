/**
 * Detect package renames from OSV for npm, PyPI, and crates.io.
 */
import type { AdvisoryEntry, Finding } from "./types.ts";
import { comparePackageVersion } from "./matcher.ts";

export type RenameEcosystem = "npm" | "pypi" | "crates.io";

export interface PackageRenameOption {
  fromPackage: string;
  toPackage: string;
  targetVersion: string;
  findingIds: string[];
  severity: Finding["severity"];
  ecosystem: RenameEcosystem;
}

function isVersionLike(value: string): boolean {
  const v = value.trim();
  return /^\d/.test(v) && !/^[0-9a-f]{8,}$/i.test(v);
}

function fixedVersionsForAffected(affected: AdvisoryEntry["affected"][number], ecosystem: string): string[] {
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
  return [...fixed].sort((a, b) => comparePackageVersion(a, b, ecosystem));
}

function pickRenameTarget(installed: string, fixes: string[], ecosystem: string): string | null {
  if (fixes.length === 0) return null;
  const eligible = fixes.filter(v => comparePackageVersion(v, installed, ecosystem) >= 0);
  if (eligible.length > 0) return eligible[0];
  return fixes.at(-1) ?? null;
}

function advisoriesForFinding(finding: Finding, advisories: AdvisoryEntry[]): AdvisoryEntry[] {
  const ids = new Set([finding.id, ...finding.aliases]);
  return advisories.filter(a =>
    ids.has(a.id) || a.aliases.some(alias => ids.has(alias)),
  );
}

function sameMajorInPlaceFix(finding: Finding): boolean {
  const installedMajor = Number.parseInt(finding.installedVersion.split(".")[0] || "0", 10);
  return (finding.fixedVersions || []).some(v => {
    const fixMajor = Number.parseInt(String(v).split(".")[0] || "0", 10);
    return comparePackageVersion(v, finding.installedVersion, finding.ecosystem) > 0 && fixMajor === installedMajor;
  });
}

function renameOptionsFromAdvisory(
  finding: Finding,
  advisory: AdvisoryEntry,
  ecosystem: RenameEcosystem,
): Array<{ toPackage: string; targetVersion: string }> {
  const from = finding.packageName;
  const options: Array<{ toPackage: string; targetVersion: string }> = [];
  const ecoLabel = ecosystem === "crates.io" ? "crates.io" : ecosystem;

  for (const affected of advisory.affected || []) {
    const name = affected.package?.name || "";
    if (!name || name === from) continue;
    const advEco = (affected.package?.ecosystem || "").toLowerCase();
    if (advEco !== ecoLabel && advEco !== ecosystem) continue;

    const fixes = fixedVersionsForAffected(affected, ecosystem);
    const target = pickRenameTarget(finding.installedVersion, fixes, ecosystem);
    if (target) options.push({ toPackage: name, targetVersion: target });
  }

  return options;
}

/** Find package rename migrations for non-Maven ecosystems. */
export function detectEcosystemRenames(
  findings: Finding[],
  advisories: AdvisoryEntry[],
  ecosystem: RenameEcosystem,
): PackageRenameOption[] {
  const results: PackageRenameOption[] = [];
  const seen = new Set<string>();
  const eco = ecosystem === "crates.io" ? "crates.io" : ecosystem;
  const byPackage = groupByPackage(findings, eco);

  for (const finding of findings) {
    if (finding.ecosystem !== eco) continue;
    if (shouldSkipPackageFinding(finding, byPackage)) continue;

    const candidates = collectCandidates(finding, advisories, ecosystem);
    addResults(results, seen, finding, candidates, ecosystem);
  }

  return results.sort((a, b) => a.fromPackage.localeCompare(b.fromPackage));
}

/** Group findings by package name for a given ecosystem */
function groupByPackage(findings: Finding[], eco: string): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.ecosystem !== eco) continue;
    const list = map.get(f.packageName);
    if (list) list.push(f);
    else map.set(f.packageName, [f]);
  }
  return map;
}

/** Check if a finding should be skipped (same-major fix available) */
function shouldSkipPackageFinding(
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
  ecosystem: RenameEcosystem,
): Map<string, string> {
  const candidates = new Map<string, string>();

  for (const advisory of advisoriesForFinding(finding, advisories)) {
    for (const opt of renameOptionsFromAdvisory(finding, advisory, ecosystem)) {
      const prev = candidates.get(opt.toPackage);
      if (!prev || comparePackageVersion(opt.targetVersion, prev, ecosystem) > 0) {
        candidates.set(opt.toPackage, opt.targetVersion);
      }
    }
  }

  return candidates;
}

/** Add rename results from candidates, deduplicating by package->target key */
function addResults(
  results: PackageRenameOption[],
  seen: Set<string>,
  finding: Finding,
  candidates: Map<string, string>,
  ecosystem: RenameEcosystem,
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
      ecosystem,
    });
  }
}

export function detectAllPackageRenames(
  findings: Finding[],
  advisories: AdvisoryEntry[],
): PackageRenameOption[] {
  return [
    ...detectEcosystemRenames(findings, advisories, "npm"),
    ...detectEcosystemRenames(findings, advisories, "pypi"),
    ...detectEcosystemRenames(findings, advisories, "crates.io"),
  ];
}
