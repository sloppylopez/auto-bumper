/**
 * Repo-published GitHub Security Advisories (GHSA) source.
 *
 * The github/advisory-database tarball only contains `advisories/github-reviewed/`.
 * Vendor-published repo advisories (netty, FasterXML jackson, ...) are missing from the
 * bulk DB entirely. Fetch them from the GitHub REST API and materialize into OSV shape
 * so matchVulnerabilities() consumes them unchanged.
 */
import fs from "node:fs";
import path from "node:path";
import type { AdvisoryEntry } from "./types.ts";
import { compareMavenVersion } from "./matcher.ts";
import { CACHE_TTL_MS } from "./osv-db.ts";
import { readCacheFile, writeCacheFile, getCacheAgeMs } from "./osv-cache.ts";
import { getOsvDbDir } from "../path.ts";
import { fetchWithRetry } from "./fetch-retry.ts";

const GHSA_REPO_CACHE = "repo-advisories";

function watchlistFile(): string {
  return path.resolve(getOsvDbDir(), "..", "..", "ghsa-repos.json");
}

export const DEFAULT_WATCHED_REPOS = [
  "netty/netty",
  "FasterXML/jackson-core",
  "FasterXML/jackson-databind",
  "FasterXML/jackson-annotations",
  "pgjdbc/pgjdbc",
];

/** Watched repos, overridable via <cacheRoot>/ghsa-repos.json (JSON array of "owner/repo"). */
export function getWatchedRepos(): string[] {
  const file = watchlistFile();
  if (fs.existsSync(file)) {
    try {
      const list = JSON.parse(fs.readFileSync(file, "utf-8"));
      if (Array.isArray(list) && list.length > 0 && list.every(r => typeof r === "string" && /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(r))) {
        return list;
      }
    } catch {
      // malformed override → fall back to defaults
    }
  }
  return DEFAULT_WATCHED_REPOS;
}

/** Parse a GHSA vulnerable_version_range: ">= A, <= B" | "<= B" | ">= A" | "= X" | "X". */
export function parseGhsaRange(rangeStr: string | null | undefined): { exact?: string; gte?: string; lte?: string } | null {
  if (!rangeStr || typeof rangeStr !== "string") return null;
  let gte: string | undefined;
  let lte: string | undefined;
  let exact: string | undefined;
  for (const part of rangeStr.split(",").map(s => s.trim()).filter(Boolean)) {
    const opMatch = /^(>=|<=|=)/.exec(part);
    let op: string;
    let val: string;
    if (opMatch) {
      op = opMatch[1];
      val = part.slice(opMatch[0].length).trim();
    } else {
      op = "=";
      val = part;
    }
    if (!val) continue;
    if (op === ">=") gte = val;
    else if (op === "<=") lte = val;
    else exact = val;
  }
  if (exact !== undefined) return { exact };
  if (gte !== undefined || lte !== undefined) return { gte, lte };
  return null;
}

const GHSA_SEVERITY_SCORE: Record<string, string> = { critical: "9.0", high: "7.5", medium: "4.0", low: "3.0" };

function firstPatchedVersion(raw: string | null | undefined, lte?: string): string | null {
  if (!raw || typeof raw !== "string") return null;
  for (const v of raw.split(",").map(s => s.trim()).filter(Boolean)) {
    // Vendor patched_versions are unreliable (e.g. "fixed:2.8.11" on a >= 2.17.0 range);
    // for Maven only accept a version strictly after the inclusive upper bound.
    if (lte !== undefined && compareMavenVersion(v, lte) <= 0) continue;
    return v;
  }
  return null;
}

/** GitHub repo security advisory as returned by the REST API (subset of fields used). */
export interface GhsaApiAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  severity?: string;
  summary?: string;
  html_url?: string;
  vulnerabilities?: Array<{
    package?: { name?: string; ecosystem?: string };
    vulnerable_version_range?: string;
    patched_versions?: string;
  }>;
}

/** One vulnerability element of a GitHub repo advisory. */
type GhsaVulnerability = NonNullable<GhsaApiAdvisory["vulnerabilities"]>[number];

/** Build one OSV affected entry from a GitHub vulnerability record (null when unusable). */
function buildAffectedEntry(v: GhsaVulnerability, ecosystems: Set<string>) {
  const pkg = v.package || {};
  if (!pkg.name || !pkg.ecosystem) return null;
  const eco = String(pkg.ecosystem).toLowerCase();
  const osvEco = eco === "maven" ? "Maven" : pkg.ecosystem;
  ecosystems.add(osvEco);

  const entry = { package: { name: pkg.name, ecosystem: osvEco }, versions: [] as string[], ranges: [] as Array<Record<string, unknown>> };
  const r = parseGhsaRange(v.vulnerable_version_range);
  if (r?.exact !== undefined) {
    entry.versions.push(r.exact);
  } else if (r) {
    const events: Array<Record<string, string>> = [{ introduced: r.gte || "0" }];
    if (r.lte !== undefined) events.push({ last_affected: r.lte });
    const fixed = firstPatchedVersion(v.patched_versions, eco === "maven" ? r.lte : undefined);
    if (fixed) events.push({ fixed });
    entry.ranges.push({ type: "ECOSYSTEM", events });
  }
  return entry;
}

/** Build the links list for a GitHub repo advisory. */
function buildGhsaLinks(advisory: GhsaApiAdvisory): Array<{ url: string }> {
  const links: Array<{ url: string }> = [];
  if (advisory.html_url) {
    links.push({ url: advisory.html_url });
  } else if (advisory.ghsa_id) {
    links.push({ url: `https://github.com/github/advisories/database/${advisory.ghsa_id}` });
  }
  if (advisory.cve_id) links.push({ url: `https://nvd.nist.gov/vuln/detail/${advisory.cve_id}` });
  return links;
}

/** Convert one GitHub repo security advisory into an OSV-shaped record (null if no usable packages). */
export function ghsaToOsv(advisory: GhsaApiAdvisory): AdvisoryEntry | null {
  const vulns = Array.isArray(advisory?.vulnerabilities) ? advisory.vulnerabilities : [];
  const affected: AdvisoryEntry["affected"] = [];
  const ecosystems = new Set<string>();

  for (const v of vulns) {
    const entry = buildAffectedEntry(v, ecosystems);
    if (!entry) continue;
    affected.push(entry);
  }

  if (affected.length === 0) return null;

  const score = GHSA_SEVERITY_SCORE[String(advisory.severity || "").toLowerCase()] ?? "3.0";

  return {
    id: advisory.ghsa_id,
    aliases: [advisory.cve_id].filter((x): x is string => Boolean(x)),
    ecosystems: [...ecosystems],
    summary: advisory.summary || `${advisory.ghsa_id} affects ${affected.map(a => a.package?.name).join(", ")}`,
    severity: [{ type: "CVSS_V3_1", score }],
    affected,
    links: buildGhsaLinks(advisory),
  };
}

export function extractNextLink(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  let from = 0;
  for (;;) {
    const start = linkHeader.indexOf("<", from);
    if (start === -1) return null;
    const end = linkHeader.indexOf(">", start + 1);
    if (end === -1 || end <= start + 1) {
      from = end === -1 ? linkHeader.length : end + 1;
      continue;
    }
    if (!/^;\s*rel="next"/.test(linkHeader.slice(end + 1))) {
      from = end + 1;
      continue;
    }
    try {
      const url = new URL(linkHeader.slice(start + 1, end));
      if (url.protocol !== "https:" || url.hostname !== "api.github.com") return null;
      return url.toString();
    } catch {
      return null;
    }
  }
}

export interface RepoAdvisoriesOptions {
  /** Bypass TTL and re-fetch */
  forceRefresh?: boolean;
  /** Spinner text updater (e.g. "GHSA advisories: netty/netty") */
  setText?: (msg: string) => void;
}

/** Fetch all pages of repo-published advisories for one repo. */
async function fetchRepoAdvisories(repo: string, setText?: (msg: string) => void): Promise<AdvisoryEntry[]> {
  const records: AdvisoryEntry[] = [];
  let url: string | null = `https://api.github.com/repos/${repo}/security-advisories?per_page=100`;
  while (url) {
    setText?.(`GHSA advisories: ${repo}`);
    const resp = await fetchWithRetry(
      url,
      { headers: { "User-Agent": "auto-bumper", Accept: "application/vnd.github+json" } },
      { label: `GitHub GHSA ${repo}`, retries: 3 },
    );
    if (!resp.ok) throw new Error(`GitHub API HTTP ${resp.status} for ${repo}`);
    const items = (await resp.json()) as GhsaApiAdvisory[];
    for (const item of items) {
      const rec = ghsaToOsv(item);
      if (rec) records.push(rec);
    }
    // This endpoint ignores `page`; pagination is cursor-based via the Link header.
    url = extractNextLink(resp.headers.get("link"));
  }
  return records;
}

/** Fetch repo-published advisories for all watched repos and cache them. */
export async function loadRepoAdvisories(opts: RepoAdvisoriesOptions = {}): Promise<AdvisoryEntry[]> {
  const { forceRefresh = false, setText } = opts;
  if (!forceRefresh) {
    const cached = readCacheFile(GHSA_REPO_CACHE);
    const age = getCacheAgeMs(GHSA_REPO_CACHE);
    if (cached !== null && age !== null && age < CACHE_TTL_MS) return cached;
  }

  const records: AdvisoryEntry[] = [];
  for (const repo of getWatchedRepos()) {
    for (const rec of await fetchRepoAdvisories(repo, setText)) records.push(rec);
  }

  writeCacheFile(GHSA_REPO_CACHE, records);
  return records;
}
