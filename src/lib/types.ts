/**
 * Core types for Auto-Bumper — local offline vulnerability scanner.
 */

export interface PackageRef {
  /** Ecosystem identifier: npm, crates.io, PyPI, Go, Maven */
  ecosystem: string;
  /** Package name (e.g., "lodash", "react") */
  name: string;
  /** Installed version (e.g., "4.5.0") */
  version: string;
  /** Path to the lockfile/manifest that declared this package */
  manifestPath: string;
}

export interface Finding {
  /** Unique identifier (typically the primary alias like GHSA or CVE) */
  id: string;
  /** All known aliases: CVE-ID, GHSA-ID, RUSTSEC, etc. */
  aliases: string[];
  /** Ecosystem where the vulnerability applies */
  ecosystem: string;
  /** Affected package name */
  packageName: string;
  /** Version currently installed */
  installedVersion: string;
  /** Human-readable vulnerable version range */
  vulnerableRange: string;
  /** Known fixed versions */
  fixedVersions: string[];
  /** Severity level */
  severity: "LOW" | "MODERATE" | "HIGH" | "CRITICAL" | "UNKNOWN";
  /** Short description of the vulnerability */
  summary: string;
  /** Reference URLs (CVE pages, advisories, commits) */
  references: string[];
}

export interface AdvisoryEntry {
  id: string;
  aliases: string[];
  ecosystems: string[];
  summary: string;
  severity: Array<{ type: string; score: string }>;
  affected: Array<{ package?: { name?: string; ecosystem?: string }; versions?: string[]; ranges?: unknown[] }>;
  links: Array<{ url: string }>;
}

/** Sort order for severity levels (higher = more severe). Used for sorting findings. */
export const SeverityOrder: Record<Finding["severity"], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/** Sort findings array by severity (descending), then by package name (ascending). */
export function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SeverityOrder[b.severity] - SeverityOrder[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.packageName.localeCompare(b.packageName);
  });
}
