/**
 * Reporter — Format vulnerability findings as markdown or JSON output.
 */
import { PRODUCT_NAME } from "./brand.ts";
import type { Finding } from "./types.ts";

interface ReportOptions {
  /** Include CVSS scores in output */
  includeScores?: boolean;
  /** Maximum findings per severity group before truncation */
  maxPerGroup?: number;
}

const DEFAULT_OPTIONS: Required<ReportOptions> = {
  includeScores: false,
  maxPerGroup: 50,
};

/** Generate a formatted markdown report from findings */
export function reportMarkdown(findings: Finding[], options?: Partial<ReportOptions>): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  if (findings.length === 0) {
    return "✅ Clean! No vulnerabilities found.";
  }

  const bySeverity = groupBySeverity(findings);

  let output = `\n🦅 **${PRODUCT_NAME} Scan Results** — ${findings.length} vulnerabilities found\n\n`;

  output += renderSummary(bySeverity);

  for (const sev of SEVERITY_ORDER) {
    const items = bySeverity[sev];
    if (!items?.length) continue;
    output += renderSection(sev, items, opts);
  }

  // References section
  const allRefs = new Set<string>();
  for (const f of findings) {
    for (const ref of f.references) {
      allRefs.add(ref);
    }
  }

  if (allRefs.size > 0 && allRefs.size <= 20) {
    output += "**References:**\n\n";
    for (const ref of allRefs) {
      output += `- ${ref}\n`;
    }
    output += "\n";
  }

  return output;
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"] as const;
const SEVERITY_EMOJI: Record<string, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MODERATE: "🟡",
  LOW: "🔵",
  UNKNOWN: "⚪",
};

/** Group findings by severity level */
function groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
  const groups: Record<string, Finding[]> = {};
  for (const f of findings) {
    if (!groups[f.severity]) groups[f.severity] = [];
    groups[f.severity].push(f);
  }
  return groups;
}

/** Render the summary line with counts per severity */
function renderSummary(bySeverity: Record<string, Finding[]>): string {
  const parts = [];
  for (const sev of SEVERITY_ORDER) {
    const count = bySeverity[sev]?.length || 0;
    if (count) parts.push(`${count} ${sev.toLowerCase()}`);
  }
  return `*${parts.join(", ")}*\n\n`;
}

/** Render a detail section for one severity level */
function renderSection(sev: string, items: Finding[], opts: Required<ReportOptions>): string {
  const emoji = SEVERITY_EMOJI[sev] ?? "⚪";
  const label = `${sev.charAt(0).toUpperCase()}${sev.slice(1).toLowerCase()}`;
  let output = `### ${emoji} ${label} (${items.length})\n\n`;
  output += "| Package | Version | Fixed | Aliases | Summary |\n";
  output += "|---------|---------|-------|---------|----------|\n";

  const displayItems = items.slice(0, opts.maxPerGroup);
  for (const f of displayItems) {
    output += renderFindingRow(f);
  }

  if (items.length > opts.maxPerGroup) {
    output += `\n*...and ${items.length - opts.maxPerGroup} more*\n`;
  }

  return output + "\n";
}

/** Render a single finding as a table row */
function renderFindingRow(f: Finding): string {
  const fixed = formatFixedVersions(f.fixedVersions);
  const aliases = f.aliases.slice(0, 2).join(", ").slice(0, 30);
  const summary = f.summary.length > 40 ? f.summary.slice(0, 40) + "…" : f.summary;
  return `| \`${f.packageName}\` | ${f.installedVersion} | ${fixed} | ${aliases} | ${summary} |\n`;
}

/** Format fixed versions list, truncating to first 3 entries */
function formatFixedVersions(versions: string[]): string {
  if (!versions.length) return "—";
  return versions.slice(0, 3).join(", ").slice(0, 20);
}

/** Generate JSON output from findings */
export function reportJson(findings: Finding[]): string {
  return JSON.stringify(findings, null, 2);
}

/** Generate a compact one-line summary */
export function reportSummary(findings: Finding[]): string {
  if (findings.length === 0) {
    return "✅ No vulnerabilities found";
  }

  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const parts = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([sev, count]) => `${count} ${sev.toLowerCase()}`);

  return `🦅 Found ${findings.length} vulnerabilities (${parts.join(", ")})`;
}

/** Count findings by severity level */
export function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}
